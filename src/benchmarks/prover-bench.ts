import type { TLSProtocolVersion } from '@reclaimprotocol/tls'
import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'
import type { ZKEngine } from '@reclaimprotocol/zk-symmetric-crypto'
import { exec as execCb } from 'node:child_process'
import { performance } from 'node:perf_hooks'
import { promisify } from 'node:util'

import { AttestorClient, createClaimOnAttestor } from '#src/client/index.ts'
import { assertValidClaimSignatures } from '#src/utils/claims.ts'
import { AttestorError } from '#src/utils/error.ts'
import { logger } from '#src/utils/logger.ts'

const execAsync = promisify(execCb)

export type ProverKind = 'gnark' | 'snarkjs'

export type ProtocolResult = {
	timeTotal?: number
	tlsHandshakeMs?: number
	onlineMs?: number
	zkProofTotal?: number
	zkGenerateMs?: number
	zkProofByte?: number
	zkVerifyAttestorMs?: number
	thirdPartyVerifyMs?: number
}

export function parseProverKind(kind: string): ProverKind {
	if(kind === 'snarkjs' || kind === 'wasm') {
		return 'snarkjs'
	}

	return 'gnark'
}

export function commandWithSudo(cmd: string, useSudo: boolean) {
	return useSudo ? `sudo ${cmd}` : cmd
}

async function runIptables(cmd: string, useSudo: boolean) {
	const full = commandWithSudo(`iptables ${cmd}`, useSudo)
	return execAsync(full)
}

export async function installIptablesCounters(
	ports: string[],
	useSudo: boolean
) {
	for(const port of ports) {
		await runIptables(`-C OUTPUT -p tcp --dport ${port} -j ACCEPT`, useSudo).catch(async() => {
			await runIptables(`-I OUTPUT -p tcp --dport ${port} -j ACCEPT`, useSudo)
		})
		await runIptables(`-C INPUT -p tcp --sport ${port} -j ACCEPT`, useSudo).catch(async() => {
			await runIptables(`-I INPUT -p tcp --sport ${port} -j ACCEPT`, useSudo)
		})
	}

	// zero entire chains to reset counters for the newly added rules
	await runIptables('-Z OUTPUT', useSudo).catch(() => undefined)
	await runIptables('-Z INPUT', useSudo).catch(() => undefined)
}

export async function cleanupIptablesCounters(
	ports: string[],
	useSudo: boolean
) {
	for(const port of ports) {
		// delete until no more matching rules
		for(;;) {
			const removed = await runIptables(`-D OUTPUT -p tcp --dport ${port} -j ACCEPT`, useSudo).then(() => true).catch(() => false)
			if(!removed) {
				break
			}
		}

		for(;;) {
			const removed = await runIptables(`-D INPUT -p tcp --sport ${port} -j ACCEPT`, useSudo).then(() => true).catch(() => false)
			if(!removed) {
				break
			}
		}
	}
}

async function readIptablesBytes(
	chain: 'INPUT' | 'OUTPUT',
	match: string,
	useSudo: boolean
) {
	const { stdout } = await runIptables(`-nvxL ${chain}`, useSudo)
	const lines = stdout.trim().split('\n').slice(2)
	let bytes = 0
	for(const line of lines) {
		if(!line.includes(match)) {
			continue
		}

		const parts = line.trim().split(/\s+/)
		if(parts.length < 2) {
			continue
		}

		const val = Number(parts[1])
		if(Number.isFinite(val)) {
			bytes += val
		}
	}

	return bytes
}

export async function readIptablesCounters(
	ports: string[],
	useSudo: boolean
) {
	let txBytes = 0
	let rxBytes = 0
	for(const port of ports) {
		txBytes += await readIptablesBytes('OUTPUT', `dpt:${port}`, useSudo)
		rxBytes += await readIptablesBytes('INPUT', `spt:${port}`, useSudo)
	}

	return { txBytes, rxBytes }
}

export async function clearQdisc(iface: string, useSudo: boolean) {
	try {
		await execAsync(commandWithSudo(`tc qdisc del dev ${iface} root`, useSudo))
	} catch(err) {
		logger.debug({ err }, 'nothing to clear on qdisc')
	}
}

export async function setNetem(iface: string, bandwidthMbps: number, latencyMs: number, useSudo: boolean) {
	await clearQdisc(iface, useSudo)
	const delay = iface === 'lo' ? latencyMs / 2 : latencyMs
	const cmd = commandWithSudo(
		`tc qdisc add dev ${iface} root netem rate ${bandwidthMbps}mbit delay ${delay}ms`,
		useSudo
	)
	await execAsync(cmd)
}

export async function showQdisc(iface: string, useSudo: boolean) {
	const cmd = commandWithSudo(`tc -s qdisc show dev ${iface}`, useSudo)
	try {
		const { stdout } = await execAsync(cmd)
		logger.info({ iface, qdisc: stdout.trim() }, 'qdisc status')
	} catch(err) {
		logger.warn({ err, iface }, 'failed to read qdisc status')
	}
}

export function round2(n: number | undefined) {
	if(n === undefined || n === null) {
		return n
	}

	return Math.round(n * 100) / 100
}


setCryptoImplementation(webcryptoCrypto)
export async function startProver(
	attestorIp = '127.0.0.1',
	attestorPort = '10000',
	httpsServerPort = '15000',
	requestSize = 1024,
	responseSize = 1024,
	tlsVersion: TLSProtocolVersion = 'TLS1_3',
	zkEngine: ZKEngine = 'gnark',
) {
	const protocolResult: ProtocolResult = {}
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
				'responselength': responseSize.toString()
			},
			responseRedactions:[{ jsonPath: 'payload' }],
			responseMatches:[{
				type:'contains',
				value: '*'
			}],
			additionalClientOptions: {
				verifyServerCertificate: true,
				supportedProtocolVersions: [tlsVersion as any],
			} as any,
		},
		onStep: (step) => {
			if(step.name === 'tls-handshake') {
				protocolResult.tlsHandshakeMs = step.ms
				logger.info({ handshakeMs: step.ms }, 'tls handshake done')

			} else if(step.name === 'request-and-response-phase') {
				protocolResult.onlineMs = step.ms
				logger.info({ onlineMs: step.ms }, 'get response done')

			} else if(step.name === 'generating-zk-proofs') {
				protocolResult.zkProofTotal = step.proofsTotal
				logger.info({ zkProofTotal: step.proofsTotal }, 'ZK generation done')

			} else if(step.name === 'zk-generate') {
				protocolResult.zkGenerateMs = step.ms
				logger.info({ zkGenerateMs: step.ms }, 'ZK generation done')

			} else if(step.name === 'zk-proof-byteLength') {
				protocolResult.zkProofByte = step.byteLength
				logger.info({ zkProofByte: step.byteLength }, 'get ZK Proof Byte done')

			} else if(step.name === 'zk-verify-attestor') {
				protocolResult.zkVerifyAttestorMs = step.ms
				logger.info({ zkVerifyAttestorMs: step.ms }, 'ZK Verification done')
			}
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

	const t0 = performance.now()
	await assertValidClaimSignatures(result)
	protocolResult.thirdPartyVerifyMs = performance.now() - t0

	const timeTotal = performance.now() - timeStart
	protocolResult.timeTotal = timeTotal
	logger.info({ timeTotal }, 'Protocol finished runtime')

	try {
		await client.terminateConnection()
	} catch(err) {
		if(!(err instanceof AttestorError && err.code === 'ERROR_NO_ERROR')) {
			throw err
		}
	}

	return protocolResult
}
