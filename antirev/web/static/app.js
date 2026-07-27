/* antiReverse 作战台前端。零构建:原生 ES module,无框架无打包。
 *
 * 数据来源只有一条 SSE 流(/api/runs/<id>/stream),四种事件:
 *   agent  —— agent 的 jsonl 事件(seq 作 SSE id,断线重连自动续传)
 *   metric —— TPS_METRICS_PATH 那份性能 jsonl
 *   status —— run 的活/暂停/猝死状态
 *   end    —— run 结束,连接关闭
 * 长 obs 只推前 2048 字符,点"展开全文"再按 seq 拉 /events/<seq>。
 */

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

// ——— 全局状态 ———
const S = {
  runId: null, es: null, replay: false,
  // maxSteps 初始为 null 而非 15:深链/回放进来时根本不知道该 run 的 max_steps,
  // 给个默认值会显示出错误的分母(实测 max_steps=8 的 run 被显示成"步 5/15")。
  step: 0, round: 0, maxSteps: null, maxReplan: 0,
  startedAt: null, budget: null, lastPrefill: null,
  agentPaused: false,              // agent 是否真的停在检查点上(区别于"暂停请求已下")
  memWarned: false,                // 内存告警去重:metric 每步都来,不去重会刷满告警区
  funcs: new Set(), reads: new Set(), verified: new Set(),
  alerts: [], pending: null,        // pending: 已收到 executor_output、等 tool_result 的那一步
};

const OBS_HEAD_LINES = 200;         // 长内容默认只渲染前 200 行,防几千行 strings 卡死 DOM
// 上下文两道线(react_executor.py:109/113):超 L1 触发按需压缩,超 L3 转 planner 归纳
const CTX_L1 = 32000;
const CTX_L3 = 45000;

// ——— 顶栏 ———
function setTop({ state, alive }) {
  const dot = $("state-dot");
  dot.className = "dot" + (state === "paused" ? " paused"
    : (state === "crashed" || state === "stopping") ? " dead" : "");
  // paused 分两个阶段:.ctl 已写 paused(请求已下)≠ agent 真的停了。agent 可能还在等
  // 一次 LLM 调用返回(几十秒),要等它到检查点才算真停 —— 直接显示"已暂停"会误导。
  const label = { running: "执行中", paused: S.agentPaused ? "已暂停" : "暂停请求中…",
                  stopping: "停止中", done: "已结束", crashed: "已崩溃",
                  history: "回放", unknown: "未知" }[state] || state;
  $("t-state").textContent = label;
  $("pause-btn").textContent = state === "paused" ? "继续" : "暂停";
  const off = !alive;
  $("pause-btn").disabled = off;
  $("stop-btn").disabled = off;
}

function tickTime() {
  if (!S.startedAt) return;
  const used = Math.floor((Date.now() - S.startedAt) / 1000);
  const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  $("t-time").textContent = S.budget ? `${fmt(used)} / ${fmt(S.budget)}` : fmt(used);
}
setInterval(tickTime, 1000);

function setRound() {
  // 深链/回放进入时不知道该 run 的 max_steps(没经过启动表单),分母只是默认值。
  // 步号一旦超过分母就说明分母不可信 —— 此时只显示步号,免得出现"步 23/15"这种怪数字。
  const total = S.maxSteps && S.step <= S.maxSteps ? "/" + S.maxSteps : "";
  $("t-round").textContent =
    `轮 ${S.round + 1}${S.maxReplan ? "/" + (S.maxReplan + 1) : ""} · 步 ${S.step}${total}`;
}

// ——— 焦点卡 / 历史时间轴 ———
function truncLines(text, n) {
  const lines = String(text).split("\n");
  return lines.length <= n
    ? { head: text, rest: 0 }
    : { head: lines.slice(0, n).join("\n"), rest: lines.length - n };
}

// 真实 agent 的 tool_result.obs 是 **dict** 而不是字符串
// (ida_decompile → {pseudocode,data_refs,…}、run_python → {stdout,stderr,returncode,…}),
// 直接交给 truncLines 会渲染成 "[object Object]"、算长度得到 undefined。
// 这里取主文本字段优先渲染,其余字段以紧凑 JSON 附在后面。
const OBS_MAIN_KEYS = ["pseudocode", "disasm", "stdout", "text", "output", "content"];
function obsText(obs) {
  if (obs == null) return "";
  if (typeof obs === "string") return obs;
  if (typeof obs !== "object") return String(obs);
  const main = OBS_MAIN_KEYS.find((k) => typeof obs[k] === "string" && obs[k].length);
  if (!main) return JSON.stringify(obs, null, 1);
  const rest = Object.fromEntries(Object.entries(obs).filter(([k]) => k !== main));
  const tail = Object.keys(rest).length
    ? `\n\n── 其余字段 ──\n${JSON.stringify(rest, null, 1)}` : "";
  return obs[main] + tail;
}

function callText(tool, args) {
  if (!tool) return "(未调用工具)";
  let a = "";
  try {
    a = Object.entries(args || {}).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ");
  } catch { a = ""; }
  return `${tool}(${a.length > 300 ? a.slice(0, 300) + "…" : a})`;
}

function renderFocus(ev) {
  const box = $("focus");
  box.className = "focus";
  box.innerHTML = "";
  box.append(el("div", "label", `当前步 #${ev.step ?? "—"}`));
  if (ev.thought) box.append(el("div", "thought", "💭 " + ev.thought));
  box.append(el("div", "call", "🔧 " + callText(ev.tool, ev.args)));
  const obs = el("div", "obs", "等待工具返回…");
  obs.id = "focus-obs";
  box.append(obs);
  box.append(hintBox());
}

function fillFocusObs(ev) {
  const obs = $("focus-obs");
  if (!obs) return;
  const { head, rest } = truncLines(obsText(ev.obs), OBS_HEAD_LINES);
  obs.textContent = head;
  const truncated = (ev._truncated || []).includes("obs");
  if (rest || truncated) {
    const more = el("span", "more",
      `▸ 展开全文${ev._obs_len ? `(共 ${ev._obs_len} 字符)` : `(还有 ${rest} 行)`}`);
    more.onclick = () => expandFull(ev.seq, obs, more);
    obs.after(more);
  }
}

async function expandFull(seq, obsNode, moreNode) {
  moreNode.textContent = "加载中…";
  try {
    const d = await (await fetch(`/api/runs/${S.runId}/events/${seq}`)).json();
    obsNode.textContent = d.obs != null ? obsText(d.obs) : obsNode.textContent;
    moreNode.remove();
  } catch (e) {
    moreNode.textContent = "加载失败:" + e;
  }
}

function pushHistory(ev, { cls = "", note = "" } = {}) {
  const row = el("div", "t" + (cls ? " " + cls : ""));
  row.append(el("b", null, "#" + (ev.step ?? "—")));
  row.append(el("code", null, ev.tool || ev.type));
  if (note) row.append(el("span", "note", note));
  row.onclick = () => toggleDetail(row, ev);
  $("history-list").prepend(row);
}

async function toggleDetail(row, ev) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("detail")) { next.remove(); return; }
  const d = el("div", "detail");
  d.append(el("div", "label", `#${ev.step ?? "—"} ${ev.type}`));
  if (ev.thought) d.append(el("div", "thought", "💭 " + ev.thought));
  if (ev.tool) d.append(el("div", "call", "🔧 " + callText(ev.tool, ev.args)));
  const body = el("div", "obs", "加载中…");
  d.append(body);
  row.after(d);
  try {
    const full = await (await fetch(`/api/runs/${S.runId}/events/${ev.seq}`)).json();
    const raw = full.obs ?? full.error ?? full.plan ?? "(无内容)";
    const { head, rest } = truncLines(obsText(raw), OBS_HEAD_LINES);
    body.textContent = head + (rest ? `\n… 还有 ${rest} 行` : "");
  } catch (e) {
    body.textContent = "加载失败:" + e;
  }
}

function hintBox() {
  const box = el("div", "hintbox");
  const inp = el("input");
  inp.placeholder = "给 agent 的提示(最高优先级,下一步即生效)";
  const btn = el("button", "primary", "发送提示");
  const send = async () => {
    const text = inp.value.trim();
    if (!text) return;
    btn.disabled = true;
    try {
      await fetch(`/api/runs/${S.runId}/hint`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      inp.value = "";
      addAlert("提示已写入,下一步生效", false);
    } finally { btn.disabled = false; }
  };
  inp.onkeydown = (e) => { if (e.key === "Enter") send(); };
  btn.onclick = send;
  box.append(el("div", "label", "💬 人工干预"), inp, btn);
  return box;
}

// ——— 告警 ———
function addAlert(text, bad = true) {
  S.alerts.unshift({ text, bad });
  const box = $("alerts");
  box.innerHTML = "";
  if (!S.alerts.length) { box.textContent = "无"; return; }
  S.alerts.slice(0, 12).forEach((a) =>
    box.append(el("div", "a" + (a.bad ? " bad" : ""), (a.bad ? "⚠ " : "· ") + a.text)));
}

// ——— 事件分发 ———
function onAgentEvent(ev) {
  // 步号统一在入口更新:flag_found / final_rejected / unsolved / step_error 都带 step,
  // 只在 executor_output 里更新会让顶栏停在最后一次工具决策的步号上(实测停在 #4 而实际已到 #7)。
  if (ev.step != null) { S.step = ev.step; setRound(); }
  switch (ev.type) {
    case "plan_md":
      S.round = ev.replan ?? 0;
      $("plan-round").textContent = "· 轮" + (S.round + 1);
      renderPlan(ev.plan || "");
      setRound();
      break;
    case "executor_output":
      S.sawStep = true;                 // 之后 metric 不再抢占焦点卡去显示 planner 进度
      if (S.pending) pushHistory(S.pending, { note: "无工具返回" });
      S.pending = ev;
      S.step = ev.step ?? S.step;
      setRound();
      renderFocus(ev);
      break;
    case "tool_result":
      fillFocusObs(ev);
      countLedger(ev);
      markPlanProgress(ev.tool);
      if (S.pending) { pushHistory({ ...S.pending, seq: ev.seq }, { note: obsNote(ev) }); S.pending = null; }
      break;
    case "flag_found":
      $("t-flag").classList.remove("hidden");
      $("t-flag").textContent = "🏁 " + ev.flag;
      S.verified.add(ev.flag);
      $("m-verified").textContent = S.verified.size || "∅";
      addAlert("出 flag:" + ev.flag, false);
      break;
    case "final_rejected":
      $("focus").classList.add("rejected");
      addAlert(`flag 被拒(${ev.reason || "未说明"}): ${ev.flag || ""}`);
      break;
    case "loop_break":
      pushHistory(ev, { cls: "warn", note: `断环 ×${ev.n ?? 1}` });
      addAlert(`断环:重复调用 ${ev.tool}`);
      break;
    case "loop_escalate_replan":
      addAlert(`反复空转 → 转 planner 重规划(${ev.tool})`);
      break;
    case "user_hint":
      pushHistory(ev, { note: "提示已被采纳" });
      addAlert("提示已被 agent 采纳", false);
      break;
    case "context_limit_replan":
      setCtx(ev.approx_tokens, true);
      addAlert(`上下文 ${ev.approx_tokens} token 触顶 → 转 planner 压缩`);
      break;
    case "paused":
      S.agentPaused = true;                       // 到这里才是真停了(agent 阻塞在检查点上)
      $("t-state").textContent = "已暂停";
      addAlert("agent 已在检查点停住", false);
      break;
    case "resumed":
      S.agentPaused = false;
      addAlert(`已恢复(暂停 ${ev.paused_s}s,时间闸已顺延)`, false);
      break;
    case "stuck_no_progress":
      addAlert(`${ev.secs}s 无新进展 → 提前判失败`);
      break;
    case "time_budget_exceeded":
      addAlert("超时间预算");
      break;
    case "unsolved":
      addAlert(`诚实退出:${ev.reason || ""}${ev.candidate ? ` (候选 ${ev.candidate})` : ""}`);
      break;
    case "step_error":
      pushHistory(ev, { cls: "err", note: "步内异常" });
      addAlert("步内异常:" + (ev.error || "").slice(0, 80));
      break;
    default:
      break;
  }
}

function obsNote(ev) {
  const n = ev._obs_len ?? obsText(ev.obs).length;   // obs 可能是 dict,不能直接取 .length
  return n > 1000 ? `${(n / 1000).toFixed(1)}k 字符` : `${n} 字符`;
}

function onMetric(m) {
  // 首个步骤出现前(planner 阶段)焦点卡是空的,用户看不出它在动 —— 实测 planner 首轮要
  // 2.5 分钟(预分析 → 带 thinking 的规划 → emit_plan 结构化,两次 LLM 调用),
  // 期间只显示"等待第一步…"会被误判成卡死。metric 每次模型调用都来,拿它当心跳。
  if (!S.sawStep) {
    S.llmCalls = (S.llmCalls || 0) + 1;
    const f = $("focus");
    f.innerHTML = "";
    f.append(el("div", "label", "PLANNER 规划中"));
    f.append(el("div", "thought",
      `⏳ 正在规划(首轮通常 1-2 分钟:确定性预分析 → 判题型 → 产出 Plan)\n`
      + `已完成 ${S.llmCalls} 次模型调用,最近一次 ${m.wall_s ?? "?"}s / ${m.tps ?? "?"} tps`));
  }
  if (m.prompt_tokens != null) {
    const k = (m.prompt_tokens / 1000).toFixed(1);
    const d = S.lastPrefill != null ? m.prompt_tokens - S.lastPrefill : null;
    $("m-prefill").textContent = `${k}k${d != null ? ` (${d >= 0 ? "↑" : "↓"}${Math.abs(d)})` : ""}`;
    S.lastPrefill = m.prompt_tokens;
    setCtx(m.prompt_tokens);        // prompt_tokens 就是真实上下文水位(比 ctx_msgs 准)
  }
  if (m.tps != null) $("m-tps").textContent = `${m.tps} tps`;
  if (m.mem_pct != null && m.mem_pct >= 0) {
    $("m-mem").textContent = `${m.mem_pct}%`;
    // 只在首次越过 90% 时告警;回落到 85% 以下才重新武装。metric 每次 LLM 调用都来,
    // 不去重会把告警区刷满同一条内存警告(实测连刷 4 条)。
    if (m.mem_pct >= 90 && !S.memWarned) {
      S.memWarned = true;
      addAlert(`内存 ${m.mem_pct}% —— 小心 mlx 被 swap 拖垮`);
    } else if (m.mem_pct < 85) {
      S.memWarned = false;
    }
  }
}

// ——— 台账 / 上下文水位 / Plan 进度 ———
function countLedger(ev) {
  const key = JSON.stringify(ev.args || {});
  if (ev.tool === "ida_decompile" || ev.tool === "ida_disasm") S.funcs.add(key);
  if (ev.tool === "ida_read_bytes") S.reads.add(key);
  $("m-funcs").textContent = S.funcs.size;
  $("m-reads").textContent = S.reads.size;
}

function setCtx(tokens, hot = false) {
  if (!tokens) return;
  $("m-ctx").textContent = `${(tokens / 1000).toFixed(1)}k / 45k`;
  const bar = $("ctx-bar");
  bar.style.width = Math.min(100, (tokens / CTX_L3) * 100) + "%";
  // 超 L1(32k)会触发按需压缩 → 黄;超 L3(45k)转 planner 归纳 → 红
  bar.className = hot || tokens >= CTX_L3 ? "hot" : (tokens >= CTX_L1 ? "warm" : "");
}

let planSteps = [];
function renderPlan(text) {
  // Plan 可能是结构化 render_plan 输出,也可能是 free-text —— emit_plan 校验失败会回退。
  // 解析不出编号步骤就只渲染全文、不显示进度,绝不报错或留空。
  const box = $("plan");
  box.innerHTML = "";
  planSteps = [];
  const lines = String(text).split("\n");
  const numbered = lines.filter((l) => /^\s*\d+[.、)]\s*\S/.test(l));
  if (numbered.length >= 2) {
    numbered.forEach((l) => {
      const node = el("div", null, l.trim());
      planSteps.push({ node, text: l.toLowerCase(), done: false });
      box.append(node);
    });
  } else {
    box.textContent = text || "—";
  }
}

function markPlanProgress(tool) {
  if (!tool || !planSteps.length) return;
  const hit = planSteps.find((s) => !s.done && s.text.includes(tool.toLowerCase()));
  if (!hit) return;
  hit.done = true;
  hit.node.className = "done";
  const next = planSteps.find((s) => !s.done);
  planSteps.forEach((s) => { if (s !== next && !s.done) s.node.className = ""; });
  if (next) next.node.className = "now";
}

// ——— SSE 连接 ———
function connect(runId, { replay = false } = {}) {
  S.runId = runId;
  S.replay = replay;
  if (S.es) S.es.close();
  const es = new EventSource(`/api/runs/${runId}/stream`);
  S.es = es;
  es.addEventListener("agent", (e) => onAgentEvent(JSON.parse(e.data)));
  es.addEventListener("metric", (e) => onMetric(JSON.parse(e.data)));
  es.addEventListener("status", (e) => {
    const st = JSON.parse(e.data);
    setTop(st);
    if (st.binary) $("t-binary").textContent = st.binary.split("/").pop();
    if (st.started && !S.startedAt) S.startedAt = st.started * 1000;
    if (st.state === "crashed" && st.stderr_tail) {
      addAlert("进程猝死,stderr:" + st.stderr_tail.slice(-200));
    }
  });
  es.addEventListener("end", (e) => {
    const d = JSON.parse(e.data);
    addAlert("run 结束:" + JSON.stringify(d.result || {}).slice(0, 120), false);
    es.close();
  });
  es.onerror = () => { /* EventSource 自己带 Last-Event-ID 重连,不必手动处理 */ };
}

// ——— 目录浏览 ———
async function browse(path) {
  const box = $("browser");
  box.classList.remove("hidden");
  box.innerHTML = "";
  let d;
  try {
    const r = await fetch("/api/fs/browse?path=" + encodeURIComponent(path || ""));
    if (!r.ok) throw new Error((await r.json()).detail || r.status);
    d = await r.json();
  } catch (e) {
    box.append(el("div", "cwd", "浏览失败:" + e.message));
    return;
  }
  box.append(el("div", "cwd", d.path));
  if (d.parent) {
    const up = el("div", "item dir", "../");
    up.onclick = () => browse(d.parent);
    box.append(up);
  }
  d.entries.forEach((e) => {
    const size = e.is_dir ? "" : `  (${(e.size / 1024).toFixed(1)} KB)`;
    const row = el("div", "item" + (e.is_dir ? " dir" : ""),
      (e.is_dir ? "📁 " : "📄 ") + e.name + size);
    row.onclick = () => {
      if (e.is_dir) { browse(e.path); return; }
      $("binary").value = e.path;
      box.classList.add("hidden");
    };
    box.append(row);
  });
}

// ——— 启动 ———
async function startRun() {
  const binary = $("binary").value.trim();
  const msg = $("launch-msg");
  if (!binary) { msg.textContent = "请先选题目二进制"; return; }
  const payload = {
    binary,
    max_replan: +$("max_replan").value || 9999,
    max_steps: +$("max_steps").value || 15,
    budget: +$("budget").value || 3600,
    stuck_seconds: +$("stuck").value || 600,
    hint: $("init-hint").value.trim() || null,
  };
  msg.textContent = "启动中…";
  let r = await fetch("/api/runs", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (r.status === 409) {
    const d = await r.json();
    if (!confirm(d.detail + "\n\n确定要并行跑吗?")) { msg.textContent = ""; return; }
    r = await fetch("/api/runs", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, force: true }),
    });
  }
  if (!r.ok) { msg.textContent = "启动失败:" + ((await r.json()).detail || r.status); return; }
  const d = await r.json();
  msg.textContent = "";
  S.maxSteps = payload.max_steps;
  S.maxReplan = payload.max_replan > 100 ? 0 : payload.max_replan;
  S.budget = payload.budget;
  S.startedAt = Date.now();
  $("t-binary").textContent = binary.split("/").pop();
  showConsole();
  connect(d.run_id);
}

function showConsole() {
  $("launch").classList.add("hidden");
  $("console").classList.remove("hidden");
}

function showLaunch() {
  if (S.es) S.es.close();
  $("console").classList.add("hidden");
  $("launch").classList.remove("hidden");
  loadHistory();
}

function resetState() {
  S.step = 0; S.round = 0; S.startedAt = null; S.pending = null; S.lastPrefill = null;
  S.maxSteps = null; S.agentPaused = false; S.memWarned = false;
  S.sawStep = false; S.llmCalls = 0;
  S.funcs.clear(); S.reads.clear(); S.verified.clear(); S.alerts = [];
  $("history-list").innerHTML = "";
  $("focus").innerHTML = '<div class="label">等待 planner 产出 Plan…</div>';
  $("plan").textContent = "—";
  $("alerts").textContent = "无";
  $("t-flag").classList.add("hidden");
  ["m-funcs", "m-reads"].forEach((i) => ($(i).textContent = "0"));
  $("m-verified").textContent = "∅";
  ["m-ctx", "m-prefill", "m-tps", "m-mem"].forEach((i) => ($(i).textContent = "—"));
  $("ctx-bar").style.width = "0";
}

// ——— 控制 ———
async function control(action) {
  if (action === "stop" && !confirm("确定停止这道题?已跑出的日志会保留。")) return;
  const r = await fetch(`/api/runs/${S.runId}/control`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action }),
  });
  if (!r.ok) { addAlert("控制失败:" + ((await r.json()).detail || r.status)); return; }
  const d = await r.json();
  if (action === "pause") {
    addAlert("暂停请求已提交 —— 若正在等模型返回,会在本次 LLM 调用结束后生效", false);
  }
  setTop({ state: d.state, alive: d.state !== "stopping" });
}

// ——— 历史 run ———
async function loadHistory() {
  const sel = $("history");
  sel.innerHTML = "";
  const { runs } = await (await fetch("/api/runs")).json();
  runs.forEach((r) => {
    const o = el("option", null,
      `${r.run_id}  [${r.state}]${r.size ? "  " + (r.size / 1024).toFixed(0) + "KB" : ""}`);
    o.value = r.run_id;
    sel.append(o);
  });
}

// ——— 事件绑定 ———
$("browse-btn").onclick = () => browse($("binary").value.trim() || "");
$("start-btn").onclick = () => { resetState(); startRun(); };
$("pause-btn").onclick = () =>
  control($("pause-btn").textContent === "继续" ? "resume" : "pause");
$("stop-btn").onclick = () => control("stop");
$("back-btn").onclick = showLaunch;
$("replay-btn").onclick = () => {
  const rid = $("history").value;
  if (!rid) return;
  resetState();
  showConsole();
  $("t-binary").textContent = rid;
  connect(rid, { replay: true });
};

// 深链:#<run_id> 直接进入该 run(刷新页面不丢现场)
if (location.hash.length > 1) {
  const rid = decodeURIComponent(location.hash.slice(1));
  resetState();
  showConsole();
  $("t-binary").textContent = rid;
  connect(rid);
} else {
  loadHistory();
}

export { S, connect, onAgentEvent, onMetric, renderPlan, setTop, browse, startRun, control };
