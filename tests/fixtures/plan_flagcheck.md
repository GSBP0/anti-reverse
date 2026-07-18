# Plan: flagcheck
## 题型判断
- 主类型: flag 校验函数
- 架构: x86-64 Linux (静态链接, 纯 syscall)
- 关键观察: 读 17 字节输入,逐字节 xor 0x37 后与内嵌 target 比较;含 "Correct"/"Wrong" 串
## 分步计划
- [ ] Step 1: solve_locate() 定位成功/失败分支地址 | 判据: 得到 find/avoid
- [ ] Step 2: solve_angr(find, avoid, stdin_len=17) 求解 | 判据: found=True,拿到候选输入
- [ ] Step 3: solve_verify(candidate, find[0], avoid[0]) 回验 | 判据: accepted=True 即为真 flag
## flag 格式
- 预期: flag{...}
