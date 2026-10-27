import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://privacyfence.github.io',
  base: '/peek/',
  markdown: {
    shikiConfig: {
      themes: {
        light: 'github-light',
        dark: 'github-dark',
      },
      defaultColor: false,
    },
  },
  build: {
    format: 'directory',
    assets: 'assets',
  },
});
