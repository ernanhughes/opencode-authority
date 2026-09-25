import { Plugin } from "@opencode/plugin";
import { authorityTools } from "./tools.ts";

const AuthorityPlugin = Plugin.define({
  id: "opencode-authority",
  async setup(ctx) {
    await ctx.tool.transform((editor) => {
      for (const tool of authorityTools()) editor.add(tool);
    });
  },
});

export default AuthorityPlugin;
