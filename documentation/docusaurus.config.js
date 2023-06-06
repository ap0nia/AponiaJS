/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Aponia Auth',
  tagline: 'Documentation for Aponia Auth',
  url: 'https://aponia-js.vercel.app',
  baseUrl: '/',
  favicon: '/favicon.ico',
  projectName: 'aponia-auth',
  themeConfig: {
    respectPrefersColorScheme: true,
    prism: {
      darkTheme: require('prism-react-renderer/themes/nightOwl'),
      theme: require('prism-react-renderer/themes/github'),
    },
    navbar: {
      title: 'tRPC + svelte',
      logo: { src: '/logo.png' },
      items: [
        {
          to: '/',
          label: 'Home',
          activeBaseRegex: '/$',
        },
        {
          href: 'https://www.npmjs.com/package/aponia',
          label: 'npm',
          position: 'right',
        },
        {
          href: 'https://github.com/ap0nia/AponiaJS',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Home',
              to: '/',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'npm',
              href: 'https://www.npmjs.com/package/aponia',
              className: 'flex items-center',
            },
            {
              label: 'GitHub',
              href: 'https://github.com/ap0nia/AponiaJS',
              className: 'flex items-center',
            },
          ],
        },
      ],
    }
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        /** @type {import('@docusaurus/preset-classic').Options['docs'] } */
        docs: {
          routeBasePath: '/',
        },
      },
    ],
  ],
};

module.exports = config;
