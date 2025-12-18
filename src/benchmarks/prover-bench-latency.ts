import type { TLSProtocolVersion } from '@reclaimprotocol/tls'
import { setCryptoImplementation } from '@reclaimprotocol/tls'
import { webcryptoCrypto } from '@reclaimprotocol/tls/webcrypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { performance } from 'node:perf_hooks'

import { startAttestorAndServer } from '#src/benchmarks/attestor-bench.ts'
import type {
	ProtocolResult,
	ProverKind,
} from '#src/benchmarks/prover-bench.ts'
import {
	cleanupIptablesCounters,
	clearQdisc,
	installIptablesCounters,
	parseProverKind,
	readIptablesCounters,
	round2,
	setNetem,
	showQdisc,
	startProver,
} from '#src/benchmarks/prover-bench.ts'
import { logger } from '#src/utils/logger.ts'

setCryptoImplementation(webcryptoCrypto)
TLS_ADDITIONAL_ROOT_CA_LIST.push(
	readFileSync('./cert/public-cert.pem', 'utf8')
)
process.env.DISABLE_BGP_CHECKS = '1'
process.env.LOG_LEVEL ??= 'info'

type SweepConfig = {
	iface: string
	bandwidthMbps: number
	latenciesMs: number[]
	requestSizeBytes: number
	responseSizeBytes: number
	attestorPort: string
	httpsPort: string
	tlsVersion: TLSProtocolVersion
	zkEngine: ProverKind
	useSudo: boolean
	outputCsv: string
	showQdisc: boolean
}

type SweepResult = {
	latencyMs: number
	runtimeMs: number
	sendBytes: number
	recvBytes: number
	memoryRssMb: number
	tlsHandshakeMs?: number
	onlineMs?: number
	zkProofTotal?: number
	zkGenerateMs?: number
	zkProofByte?: number
	zkVerifyAttestorMs?: number
	thirdPartyVerifyMs?: number
	error?: string
}

const DEFAULT_CONFIG: SweepConfig = {
	iface: process.env.BENCH_IFACE ?? 'lo',
	bandwidthMbps: +(process.env.BENCH_BANDWIDTH_MBPS ?? 1000),
	latenciesMs: (process.env.BENCH_LATENCIES_MS ?? '10,25,50,100,200')
		.split(',')
		.map(s => +s)
		.filter(n => !Number.isNaN(n) && n > 0),
	requestSizeBytes: +(process.env.BENCH_REQUEST_BYTES ?? 1024),
	responseSizeBytes: +(process.env.BENCH_RESPONSE_BYTES ?? 4096),
	attestorPort: process.env.BENCH_ATTESTOR_PORT ?? '10000',
	httpsPort: process.env.BENCH_HTTPS_PORT ?? '15000',
	tlsVersion: (process.env.BENCH_TLS as TLSProtocolVersion) ?? (process.argv[2] as TLSProtocolVersion) ?? 'TLS1_3',
	zkEngine: parseProverKind(process.env.BENCH_KIND ?? process.argv[3] ?? 'gnark'),
	useSudo: process.env.BENCH_SUDO !== '0',
	outputCsv: process.env.BENCH_CSV ?? join('benchmarks', 'prover-bench-latency.csv'),
	showQdisc: process.env.BENCH_SHOW_QDISC === '1',
}

function writeCsv(results: SweepResult[], config: SweepConfig) {
	mkdirSync(dirname(config.outputCsv), { recursive: true })
	const header = [
		'kind',
		'name',
		'bandwidth(Mbps)',
		'latency(ms)',
		'request_size(B)',
		'response_size(B)',
		'runtime(ms)',
		'send_bytes(B)',
		'recv_bytes(B)',
		'memory_rss(MB)',
		'tls_handshake_ms',
		'online_ms',
		'zk_proof_total',
		'zk_generate_ms',
		'zk_proof_bytes',
		'zk_verify_attestor_ms',
		'third_party_verify_ms',
		'error',
	].join(',')
	const rows = results.map(result => {
		const runtime = Number.isFinite(result.runtimeMs) ? result.runtimeMs.toFixed(2) : ''
		const memory = Number.isFinite(result.memoryRssMb) ? result.memoryRssMb.toFixed(2) : ''
		return [
			config.zkEngine,
			`${config.tlsVersion}-${config.zkEngine}`,
			config.bandwidthMbps,
			result.latencyMs,
			config.requestSizeBytes,
			config.responseSizeBytes,
			runtime,
			result.sendBytes,
			result.recvBytes,
			memory,
			result.tlsHandshakeMs ?? '',
			result.onlineMs ?? '',
			result.zkProofTotal ?? '',
			result.zkGenerateMs ?? '',
			result.zkProofByte ?? '',
			result.zkVerifyAttestorMs ?? '',
			result.thirdPartyVerifyMs ?? '',
			result.error ?? '',
		].join(',')
	})
	writeFileSync(config.outputCsv, [header, ...rows].join('\n'))
}

function printSummary(results: SweepResult[]) {
	const table = results.map(result => ({
		latency: `${result.latencyMs} ms`,
		runtimeMs: Number.isFinite(result.runtimeMs) ? result.runtimeMs.toFixed(2) : 'NaN',
		sendBytes: result.sendBytes,
		recvBytes: result.recvBytes,
		memoryRssMb: Number.isFinite(result.memoryRssMb) ? result.memoryRssMb.toFixed(2) : 'NaN',
		tlsHandshakeMs: result.tlsHandshakeMs ?? '',
		onlineMs: result.onlineMs ?? '',
		zkProofTotal: result.zkProofTotal ?? '',
		zkGenerateMs: result.zkGenerateMs ?? '',
		zkVerifyAttestorMs: result.zkVerifyAttestorMs ?? '',
		thirdPartyVerifyMs: result.thirdPartyVerifyMs ?? '',
		error: result.error ?? '',
	}))
	console.table(table)
}

async function warmup(config: SweepConfig) {
	for(let i = 0; i < 3; i++) {
		await startProver(
			'127.0.0.1', config.attestorPort, config.httpsPort,
			1, 1, config.tlsVersion, config.zkEngine,
		)
	}
}

async function sweepLatencies(config: SweepConfig) {
	logger.info(
		{
			iface: config.iface,
			bandwidthMbps: config.bandwidthMbps,
			latenciesMs: config.latenciesMs,
			requestSizeBytes: config.requestSizeBytes,
			responseSizeBytes: config.responseSizeBytes,
			tlsVersion: config.tlsVersion,
			zkEngine: config.zkEngine,
		},
		'starting latency sweep'
	)

	await startAttestorAndServer()
	const results: SweepResult[] = []
	const ports = [config.attestorPort, config.httpsPort]

	await warmup(config)

	for(const latency of config.latenciesMs) {
		for(let i = 0; i < 10; i++) {
			await cleanupIptablesCounters(ports, config.useSudo)
			await installIptablesCounters(ports, config.useSudo)

			await setNetem(config.iface, config.bandwidthMbps, latency, config.useSudo)
			if(config.showQdisc) {
				await showQdisc(config.iface, config.useSudo)
			}

			const timeStart = performance.now()
			const memBefore = process.memoryUsage().rss
			let runtimeMs = NaN
			let error: string | undefined
			let memoryRssMb = NaN
			let sendBytes = config.requestSizeBytes
			let recvBytes = config.responseSizeBytes
			let protocolResult: ProtocolResult | undefined

			try {
				protocolResult = await startProver(
					'127.0.0.1',
					config.attestorPort,
					config.httpsPort,
					config.requestSizeBytes,
					config.responseSizeBytes,
					config.tlsVersion,
					config.zkEngine,
				)
				runtimeMs = protocolResult?.timeTotal ?? (performance.now() - timeStart)
				const memAfter = process.memoryUsage().rss
				memoryRssMb = memAfter / (1024 * 1024)
			} catch(err) {
				error = err instanceof Error ? err.message : String(err)
				runtimeMs = performance.now() - timeStart
				memoryRssMb = memBefore / (1024 * 1024)
				logger.error({ err, latency }, 'prover run failed')
			} finally {
				await clearQdisc(config.iface, config.useSudo)
				const { txBytes, rxBytes } = await readIptablesCounters([config.attestorPort, config.httpsPort], config.useSudo)
				sendBytes = txBytes
				recvBytes = rxBytes
				await cleanupIptablesCounters([config.attestorPort, config.httpsPort], config.useSudo)
			}

			const roundedRuntime = round2(runtimeMs)
			const roundedMemory = round2(memoryRssMb)
			const roundedHandshake = round2(protocolResult?.tlsHandshakeMs)
			const roundedOnline = round2(protocolResult?.onlineMs)
			const roundedZkGen = round2(protocolResult?.zkGenerateMs)
			const roundedZkBytes = round2(protocolResult?.zkProofByte)
			const roundedZkVerify = round2(protocolResult?.zkVerifyAttestorMs)
			const roundedThirdVerify = round2(protocolResult?.thirdPartyVerifyMs)

			results.push({
				latencyMs: latency,
				runtimeMs: roundedRuntime ?? NaN,
				sendBytes,
				recvBytes,
				memoryRssMb: roundedMemory ?? NaN,
				tlsHandshakeMs: roundedHandshake,
				onlineMs: roundedOnline,
				zkProofTotal: protocolResult?.zkProofTotal,
				zkGenerateMs: roundedZkGen,
				zkProofByte: roundedZkBytes,
				zkVerifyAttestorMs: roundedZkVerify,
				thirdPartyVerifyMs: roundedThirdVerify,
				error,
			})
			logger.info({
				latency,
				runtimeMs: roundedRuntime,
				sendBytes,
				recvBytes,
				memoryRssMb: roundedMemory,
				tlsHandshakeMs: roundedHandshake,
				onlineMs: roundedOnline,
				zkProofTotal: protocolResult?.zkProofTotal,
				zkGenerateMs: roundedZkGen,
				zkProofByte: roundedZkBytes,
				zkVerifyAttestorMs: roundedZkVerify,
				thirdPartyVerifyMs: roundedThirdVerify,
				error,
			}, 'finished one latency run')
		}
	}

	writeCsv(results, config)
	printSummary(results)
	process.exit(0)
}

async function main() {
	await sweepLatencies(DEFAULT_CONFIG)
}

main().catch(err => {
	logger.error({ err }, 'latency sweep failed')
	process.exit(1)
})
