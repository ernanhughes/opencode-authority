import { Plugin } from "@opencode/plugin";
import { CanaryWriteTool, registerAuthorityGate } from "./hooks.ts";
import { authorityTools } from "./tools.ts";

const AuthorityPlugin = Plugin.define({
  id: "opencode-authority",
  async setup(ctx) {
    await ctx.tool.transform((editor) => {
      for (const tool of authorityTools()) editor.add(tool);
      editor.add(CanaryWriteTool());
    });
    await registerAuthorityGate(ctx as never);
  },
});

export default AuthorityPlugin;
