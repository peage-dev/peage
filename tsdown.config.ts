import { defineConfig } from 'tsdown'

export default defineConfig({
  workspace: {
    include: ['packages/*'],
    exclude: ['packages/tests'],
  },
  entry: 'src/index.ts',
  dts: { generator: 'oxc' },
  exports: { devExports: true },
  publint: true,
  attw: { profile: 'esm-only' },
})
