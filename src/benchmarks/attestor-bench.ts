import * as parseCertificateNS from '@reclaimprotocol/tls'
import '#src/server/utils/config-env.ts'

const parseCertificate = { ...parseCertificateNS } as any
parseCertificate.verifyCertificateChain = () => true

import { createMockServer } from '#src/benchmarks/server-bench.ts'
import { createServer } from '#src/server/create-server.ts'

export async function startAttestorAndServer() {
	const attestorPort = 10000
	const httpServerPort = 15000

	const mockHttpsServer = createMockServer(httpServerPort)
	console.log('Https Server started at:', httpServerPort)

	const attestorServer = createServer(attestorPort)
	console.log('Attestor Server started at:', attestorPort)
	return { attestor: attestorServer, httpsServer: mockHttpsServer }
}