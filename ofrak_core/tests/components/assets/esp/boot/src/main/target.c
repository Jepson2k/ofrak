/*
 * Ordinary helper that app_main genuinely calls. The OFRAK test redirects
 * app_main's call to this function over to an injected replacement and proves
 * the printed value changes. It lives in its own translation unit and is marked
 * noinline so the compiler emits a real call instruction (call8 on Xtensa, jal
 * on RISC-V) for the redirect to retarget.
 */
__attribute__((noinline)) int target(int n)
{
    return n;
}
