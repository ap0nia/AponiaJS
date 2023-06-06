/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Aponia Auth',
  tagline: 'Documentation for Aponia Auth',
  url: 'https://aponia-js.vercel.app',
  baseUrl: '/',
  favicon: 'img/favicon.ico',
  projectName: 'aponia-auth',
  themeConfig: {
    disableSwitch: false,
    respectPrefersColorScheme: true,
    prism: {
      darkTheme: require('prism-react-renderer/themes/nightOwl'),
      theme: require('prism-react-renderer/themes/github'),
    },
    navbar: {
      title: 'tRPC + svelte',
      logo: { src: 'img/logo.png' }, 
      items: [
        {
          to: '/',
          label: 'Home',
          activeBaseRegex: '/$',
        },
        {
          href: 'https://github.com/bevm0/trpc-svelte-toolbox.git',
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
              label: 'GitHub',
              href: 'https://github.com/bevm0/trpc-svelte-toolbox.git',
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
        docs: {
          routeBasePath: '/',
        },
      },
    ],
  ],
};

module.exports = config;
