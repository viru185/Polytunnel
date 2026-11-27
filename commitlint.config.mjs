// Conventional Commits, checked in CI (wagoid/commitlint-github-action).
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // Dependabot and release-please write long lines in bodies and footers.
    'body-max-line-length': [0],
    'footer-max-line-length': [0],
  },
};
