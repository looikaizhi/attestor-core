// scripts/run-prover-bench.ts
import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'
import { performance } from 'node:perf_hooks'

import { startAttestorAndServer } from '#src/benchmarks/attestor-bench.ts'
import { AttestorClient, createClaimOnAttestor } from '#src/client/index.ts'
import { decryptTranscript } from '#src/server/index.ts'
import { assertValidClaimSignatures } from '#src/utils/claims.ts'
import { getTranscriptString } from '#src/utils/generics.ts'
import { logger } from '#src/utils/logger.ts'

setCryptoImplementation(webcryptoCrypto)
// ------------- config -------------
const ATTESTOR_PORT = 10000
const HTTPS_PORT = 15000
const REQUEST_SIZE = 1024 // bytes
const RESPONSE_SIZE = 1024 // bytes,可改
const TLS_VERSION = 'TLS1_3'
// ---------------------------------

async function main() {
	process.env.DISABLE_BGP_CHECKS = '1'

	await startAttestorAndServer()
	logger.info({ ATTESTOR_PORT }, 'attestor up')

	const client = new AttestorClient({
		url: `ws://127.0.0.1:${ATTESTOR_PORT}/ws`,
		logger: logger.child({ client: 1 }),
	})
	await client.waitForInit()

	const user = 'bench-user'
	const body = 'a'.repeat(REQUEST_SIZE)
	const t0 = performance.now()
	const result = await createClaimOnAttestor({
		name: 'http',
		params: {
			url: `https://localhost:${HTTPS_PORT}/me`,
			method: 'POST',
			body,
			headers: { responseLength: RESPONSE_SIZE.toString() },
			responseRedactions: [{ jsonPath: 'payload' }],
			responseMatches: [{ type: 'contains', value: '*' }],
			additionalClientOptions: {
				verifyServerCertificate: false,
				supportedProtocolVersions: [TLS_VERSION as any],
			} as any,
		},
		secretParams: { authorisationHeader: `Bearer ${user}` },
		ownerPrivateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
		client,
		zkEngine: 'gnark',
	})
	const ms = performance.now() - t0

	if(result.error) {
		logger.error({ err: result.error }, 'createClaim failed')
	} else {
		await assertValidClaimSignatures(result)
		logger.info({ ms }, 'prover bench success')

		const transcript = result.request!.transcript
		const decTranscript = await decryptTranscript(
			transcript, logger, 'gnark',
            result.request?.fixedServerIV!, result.request?.fixedClientIV!
		)

		// convert the transcript to a string for easy viewing
		const transcriptStr = getTranscriptString(decTranscript)
		console.log('receipt:\n', transcriptStr)
	}

}

main().catch(err => {
	console.error(err)
	process.exit(1)
})
