// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://sidereal.cloud',
	integrations: [
		starlight({
			title: 'Sidereal',
			description: 'Continuous security control validation for Kubernetes',
			logo: {
				src: './src/assets/sidereal-icon.svg',
				alt: 'Sidereal',
			},
			favicon: '/favicon.svg',
			customCss: ['./src/styles/custom.css'],
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/primaris-tech/sidereal' }],
			editLink: {
				baseUrl: 'https://github.com/primaris-tech/sidereal/edit/main/website/',
			},
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Introduction', slug: 'getting-started/introduction' },
						{ label: 'Installation', slug: 'getting-started/installation' },
						{ label: 'Your First Probe', slug: 'getting-started/first-probe' },
						{ label: 'Discovery', slug: 'getting-started/discovery' },
					],
				},
				{
					label: 'Concepts',
					items: [
						{ label: 'How Sidereal Works', slug: 'concepts/how-it-works' },
						{ label: 'Probe Types', slug: 'concepts/probe-types' },
						{ label: 'Execution Modes', slug: 'concepts/execution-modes' },
						{ label: 'Control Effectiveness', slug: 'concepts/control-effectiveness' },
						{ label: 'HMAC Integrity', slug: 'concepts/hmac-integrity' },
						{ label: 'Compliance Mapping', slug: 'concepts/compliance-mapping' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'Detection Probes with Falco', slug: 'guides/detection-falco' },
						{ label: 'SIEM Export', slug: 'guides/siem-export' },
						{ label: 'Report Generation', slug: 'guides/reports' },
						{ label: 'Custom Probes', slug: 'guides/custom-probes' },
						{ label: 'Namespace Selectors', slug: 'guides/namespace-selectors' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'CRD Reference', slug: 'reference/crds' },
						{ label: 'Helm Values', slug: 'reference/helm-values' },
						{ label: 'Deployment Profiles', slug: 'reference/deployment-profiles' },
						{ label: 'Compliance Frameworks', slug: 'reference/frameworks' },
						{ label: 'CLI', slug: 'reference/cli' },
					],
				},
				{
					label: 'Project',
					items: [
						{ label: 'License', slug: 'license' },
						{ label: 'Privacy', slug: 'privacy' },
					],
				},
			],
		}),
	],
});
