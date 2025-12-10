import type { TLSProtocolVersion } from '@reclaimprotocol/tls'
import type { ZKEngine } from '@reclaimprotocol/zk-symmetric-crypto'
import { performance } from 'node:perf_hooks'

import { AttestorClient, createClaimOnAttestor } from '#src/client/index.ts'
import { providers } from '#src/providers/index.ts'
import { assertValidClaimSignatures } from '#src/utils/claims.ts'
import { logger } from '#src/utils/logger.ts'

export async function startProver(
	attestorIp = '127.0.0.1',
	attestorPort = 10000,
	httpsServerPort = 15000,
	requestSize = 1024,
	responseSize = 1024,
	tlsVersion: TLSProtocolVersion = 'TLS1_3',
	zkEngine: ZKEngine = 'gnark',
) {

	providers.http.additionalClientOptions = {
		verifyServerCertificate: true,
		supportedProtocolVersions: [tlsVersion]
	}

	const attestorUrl = `ws://${attestorIp}:${attestorPort}/ws`
	const client = new AttestorClient({
		logger: logger.child({ client:1 }),
		url: attestorUrl,
	})
	await client.waitForInit()

	const user = 'adhiraj'
	const httpsUrl = `https://localhost:${httpsServerPort}/me`
	const body = 'a'.repeat(requestSize)
	const timeStart = performance.now()
	const result = await createClaimOnAttestor({
		name: 'http',
		params:{
			url: httpsUrl,
			method: 'POST',
			body: body,
			headers:{
				'responseLength': responseSize.toString()
			},
			responseRedactions:[{ jsonPath: 'd' }],
			responseMatches:[{
				type:'contains',
				value: '0'
			}]
		},
		secretParams:{
			authorisationHeader: `Bearer ${user}`
		},
		ownerPrivateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
		client: client,
		zkEngine: zkEngine,
	})

	if(result.error) {
		console.error('error in creating claim', result.error)
		return
	}

	await assertValidClaimSignatures(result)
	const timeTotal = performance.now() - timeStart
	logger.info({ timeTotal }, 'Protocol finished runtime')

	await client.terminateConnection()
}