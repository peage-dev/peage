import { defineConfig } from 'tsdown'

function withWorkspaceTesting(
  exports: Record<string, unknown>,
  { isPublish }: { isPublish: boolean },
): Record<string, unknown> {
  if (isPublish) {
    return exports
  }
  return { ...exports, './testing': './src/testing.ts' }
}

export default defineConfig({
  platform: 'neutral',
  exports: { devExports: true, customExports: withWorkspaceTesting },
})
