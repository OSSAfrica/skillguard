// Defense in depth. Native permissions also deny these tools; the MCP server
// uses codemode:false so no general Code Mode executor needs to be allowed.
export default {
  id: "ossafrica.skillguard",
  async setup(ctx) {
    const deny = () => { throw new Error("SkillGuard: direct execution is quarantined. Use the protected SkillGuard tools; do not retry through another executor."); };
    await ctx.tool.hook("execute.before", (event) => {
      if (["execute", "bash", "shell", "terminal", "code", "subagent"].includes(event.tool)) deny();
    });
    await ctx.shell.hook("create.before", deny);
  },
};
