import { defineConfig } from 'oxlint'

export default defineConfig({
  categories: {
    correctness: 'error',
    perf: 'warn',
    suspicious: 'warn',
  },
  env: {
    builtin: true,
  },
  ignorePatterns: ['dist'],
  plugins: ['typescript', 'unicorn', 'oxc'],
  rules: {
    'func-style': 'off',
  },
})
