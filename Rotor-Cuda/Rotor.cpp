#include "Rotor.h"
#include "GmpUtil.h"
#include "Base58.h"
#include "sha256.cpp"
#include "hash/keccak160.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <sstream>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#ifdef WIN64
#include <Windows.h>
#endif

using namespace std;

// Remove CPU_GRP_SIZE static Points
// Remove _2Gn and Gn

// ----------------------------------------------------------------------------

Rotor::Rotor(const std::string& inputFile, int compMode, int searchMode, int coinType, bool useGpu,
	const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey, int nbit2, int next, int zet, int display,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->inputFile = inputFile;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->nbit2 = nbit2;
	this->next = next;
	this->zet = zet;
	this->display = display;
	this->stroka = stroka;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeStart8.SetBase16(rangeStart.c_str());
	this->rhex.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->rangeDiffbar.Set(&this->rangeDiff2);
	this->rangeDiffcp.Set(&this->rangeDiff2);
	this->lastrKey = 0;

	secp = new Secp256K1();
	secp->Init();

	// load file
	FILE* wfd;
	uint64_t N = 0;

	wfd = fopen(this->inputFile.c_str(), "rb");
	if (!wfd) {
		printf("  %s can not open\n", this->inputFile.c_str());
		exit(1);
	}

#ifdef WIN64
	_fseeki64(wfd, 0, SEEK_END);
	N = _ftelli64(wfd);
#else
	fseek(wfd, 0, SEEK_END);
	N = ftell(wfd);
#endif

	int K_LENGTH = 20;
	if (this->searchMode == (int)SEARCH_MODE_MX)
		K_LENGTH = 32;

	N = N / K_LENGTH;
	rewind(wfd);

	DATA = (uint8_t*)malloc(N * K_LENGTH);
	memset(DATA, 0, N * K_LENGTH);

	uint8_t* buf = (uint8_t*)malloc(K_LENGTH);;

	bloom = new Bloom(2 * N, 0.000001);

	uint64_t percent = (N - 1) / 100;
	uint64_t i = 0;
	printf("\n");
	while (i < N && !should_exit) {
		memset(buf, 0, K_LENGTH);
		memset(DATA + (i * K_LENGTH), 0, K_LENGTH);
		if (fread(buf, 1, K_LENGTH, wfd) == K_LENGTH) {
			bloom->add(buf, K_LENGTH);
			memcpy(DATA + (i * K_LENGTH), buf, K_LENGTH);
			if ((percent != 0) && i % percent == 0) {
				printf("\r  Loading      : %llu %%", (i / percent));
				fflush(stdout);
			}
		}
		i++;
	}
	fclose(wfd);
	free(buf);

	if (should_exit) {
		delete secp;
		delete bloom;
		if (DATA)
			free(DATA);
		exit(0);
	}

	BLOOM_N = bloom->get_bytes();
	TOTAL_COUNT = N;
	targetCounter = i;
	if (coinType == COIN_BTC) {
		if (searchMode == (int)SEARCH_MODE_MA)
			printf("\n  Loaded       : %s Bitcoin addresses\n", formatThousands(i).c_str());
		else if (searchMode == (int)SEARCH_MODE_MX)
			printf("\n  Loaded       : %s Bitcoin xpoints\n", formatThousands(i).c_str());
	}
	else {
		printf("\n  Loaded       : %s Ethereum addresses\n", formatThousands(i).c_str());
	}

	printf("\n");

	bloom->print();
	printf("\n");

	InitGenratorTable();

}

// ----------------------------------------------------------------------------

Rotor::Rotor(const std::vector<unsigned char>& hashORxpoint, int compMode, int searchMode, int coinType,
	bool useGpu, const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey, int nbit2, int next, int zet, int display,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->next = next;
	this->zet = zet;
	this->display = display;
	this->stroka = stroka;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeStart8.SetBase16(rangeStart.c_str());
	this->rhex.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->rangeDiffcp.Set(&this->rangeDiff2);
	this->rangeDiffbar.Set(&this->rangeDiff2);
	this->targetCounter = 1;
	this->nbit2 = nbit2;
	secp = new Secp256K1();
	secp->Init();

	if (this->searchMode == (int)SEARCH_MODE_SA) {
		assert(hashORxpoint.size() == 20);
		for (size_t i = 0; i < hashORxpoint.size(); i++) {
			((uint8_t*)hash160Keccak)[i] = hashORxpoint.at(i);
		}
	}
	else if (this->searchMode == (int)SEARCH_MODE_SX) {
		assert(hashORxpoint.size() == 32);
		for (size_t i = 0; i < hashORxpoint.size(); i++) {
			((uint8_t*)xpoint)[i] = hashORxpoint.at(i);
		}
	}
	printf("\n");

	InitGenratorTable();
}

// ----------------------------------------------------------------------------

void Rotor::InitGenratorTable()
{
	char* ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	printf("  Start Time   : %s", ctimeBuff);
}

// ----------------------------------------------------------------------------

Rotor::~Rotor()
{
	delete secp;
	if (searchMode == (int)SEARCH_MODE_MA || searchMode == (int)SEARCH_MODE_MX)
		delete bloom;
	if (DATA)
		free(DATA);
}

// ----------------------------------------------------------------------------

double log1(double x)
{
	// Use taylor series to approximate log(1-x)
	return -x - (x * x) / 2.0 - (x * x * x) / 3.0 - (x * x * x * x) / 4.0;
}

void Rotor::output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey)
{
#ifdef WIN64
	WaitForSingleObject(ghMutex, INFINITE);
#else
	// Remove pthread_mutex_lock(&ghMutex);
#endif

	FILE* f = stdout;
	bool needToClose = false;

	if (outputFile.length() > 0) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("  Cannot open %s for writing\n", outputFile.c_str());
			f = stdout;
		}
		else {
			needToClose = true;
		}
	}

	if (!needToClose)
		printf("\n");
	fprintf(f, "PubAddress: %s\n", addr.c_str());
	fprintf(stdout, "\n  =================================================================================\n");
	fprintf(stdout, "  PubAddress: %s\n", addr.c_str());

	if (coinType == COIN_BTC) {
		fprintf(f, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
		fprintf(stdout, "  Priv (WIF): p2pkh:%s\n", pAddr.c_str());
	}

	fprintf(f, "Priv (HEX): %s\n", pAddrHex.c_str());
	fprintf(stdout, "  Priv (HEX): %s\n", pAddrHex.c_str());

	fprintf(f, "PubK (HEX): %s\n", pubKey.c_str());
	fprintf(stdout, "  PubK (HEX): %s\n", pubKey.c_str());

	fprintf(f, "=================================================================================\n");
	fprintf(stdout, "  =================================================================================\n");

	if (needToClose)
		fclose(f);

#ifdef WIN64
	ReleaseMutex(ghMutex);
#else
	// Remove pthread_mutex_unlock(&ghMutex);
#endif
}

// ----------------------------------------------------------------------------

bool Rotor::checkPrivKey(std::string addr, Int& key, int32_t incr, bool mode)
{
	Int k(&key), k2(&key);
	k.Add((uint64_t)incr);
	k2.Add((uint64_t)incr);
	Point p = secp->ComputePublicKey(&k);
	std::string px = p.x.GetBase16();
	std::string chkAddr = secp->GetAddress(mode, p);
	if (chkAddr != addr) {
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		std::string chkAddr = secp->GetAddress(mode, p);
		if (chkAddr != addr) {
			printf("\n=================================================================================\n");
			printf("  Warning, wrong private key generated !\n");
			printf("  PivK : %s\n", k2.GetBase16().c_str());
			printf("  Addr : %s\n", addr.c_str());
			printf("  PubX : %s\n", px.c_str());
			printf("  PivK : %s\n", k.GetBase16().c_str());
			printf("  Check: %s\n", chkAddr.c_str());
			printf("  PubX : %s\n", p.x.GetBase16().c_str());
			printf("=================================================================================\n");
			return false;
		}
	}
	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

bool Rotor::checkPrivKeyETH(std::string addr, Int& key, int32_t incr)
{
	Int k(&key), k2(&key);
	k.Add((uint64_t)incr);
	k2.Add((uint64_t)incr);
	Point p = secp->ComputePublicKey(&k);
	std::string px = p.x.GetBase16();
	std::string chkAddr = secp->GetAddressETH(p);
	if (chkAddr != addr) {
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		std::string chkAddr = secp->GetAddressETH(p);
		if (chkAddr != addr) {
			printf("\n=================================================================================\n");
			printf("  Warning, wrong private key generated !\n");
			printf("  PivK :%s\n", k2.GetBase16().c_str());
			printf("  Addr :%s\n", addr.c_str());
			printf("  PubX :%s\n", px.c_str());
			printf("  PivK :%s\n", k.GetBase16().c_str());
			printf("  Check:%s\n", chkAddr.c_str());
			printf("  PubX :%s\n", p.x.GetBase16().c_str());
			printf("=================================================================================\n");
			return false;
		}
	}
	output(addr, k.GetBase16(), k.GetBase16(), secp->GetPublicKeyHexETH(p));
	return true;
}

bool Rotor::checkPrivKeyX(Int& key, int32_t incr, bool mode)
{
	Int k(&key);
	k.Add((uint64_t)incr);
	Point p = secp->ComputePublicKey(&k);
	std::string addr = secp->GetAddress(mode, p);
	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

// ----------------------------------------------------------------------------
// Remove all checkMultiAddresses/checkMultiAddressesETH/checkSingleAddress/checkSingleAddressETH/checkMultiXPoints/checkSingleXPoint
// Remove all checkMultiAddressesSSE/checkSingleAddressesSSE

// ----------------------------------------------------------------------------
// Remove getCPUStartingKey
// Remove FindKeyCPU

// ----------------------------------------------------------------------------
void Rotor::getGPUStartingKeys(Int & tRangeStart, Int & tRangeEnd, int groupSize, int nbThread, Int * keys, Point * p)
{
	// ... (code is unchanged, as in your original GPU code)
	// This function is already GPU only
	// Keep as is.
	// (Copy-paste from original)
	if (rKey > 0) {
		if (rangeDiff2.GetBitLength() > 1) {
			if (rKeyCount2 == 0) {
				if (display > 0) {
					printf("  Base Key     : Randomly changes %d start Private keys every %llu,000,000,000 on the counter\n", nbThread, rKey);
					printf("  ROTOR Random : Min %d (bit) %s \n", rangeStart.GetBitLength(), rangeStart.GetBase16().c_str());
					printf("  ROTOR Random : Max %d (bit) %s \n\n", rangeEnd.GetBitLength(), rangeEnd.GetBase16().c_str());
				}
			}
			for (int i = 0; i < nbThread; i++) {
				gpucores = i;
				keys[i].Rand2(&rangeStart8, &rangeEnd);;
				rhex = keys[i];
				Int k(keys + i);
				k.Add((uint64_t)(groupSize / 2));
				p[i] = secp->ComputePublicKey(&k);
			}
		}
		else {
			if (next > 0) {

				if (rKeyCount2 == 0) {

					if (next > 256) {
						printf("\n  ROTOR Random : Are you serious %d bit ??? \n", next);
						exit(1);
					}
					if (zet > 256) {
						printf("\n  ROTOR Random : Are you serious -z %d bit ??? \n", zet);
						exit(1);
					}
					if (zet < 1) {
						if (display > 0) {
							printf("  ROTOR Random : Private keys random %d (bit)  \n", next);
						}
					}
					else {
						if (display > 0) {
							printf("  ROTOR Random : Private keys random %d (bit) <~> %d (bit)\n", next, zet);
						}
					}
					if (display > 0) {
						printf("  Base Key     : Randomly changes %d start Private keys every %llu,000,000,000 on the counter\n\n", nbThread, rKey);
					}
				}
				for (int i = 0; i < nbThread; i++) {
					gpucores = i;
					int next2 = 0;
					if (zet < 1) {
						keys[i].Rand(next);
						rhex = keys;
						Int k(keys + i);
						k.Add((uint64_t)(groupSize / 2));
						p[i] = secp->ComputePublicKey(&k);
					}
					else {
						if (zet <= next) {
							printf("\n  ROTOR Random : Are you serious -n %d (start) -z %d (end) ??? \n  The start must be less than the end \n", next, zet);
							exit(1);
						}
						int dfs = zet - next;
						srand(time(NULL));
						int next3 = next + rand() % dfs;
						next2 = next3 + rand() % 2;
						keys[i].Rand(next2);
						rhex = keys;
						Int k(keys + i);
						k.Add((uint64_t)(groupSize / 2));
						p[i] = secp->ComputePublicKey(&k);
					}
				}
			}
			else {
				if (rKeyCount2 == 0) {
					if (display > 0) {
						printf("  Rotor Random : Private keys random 95%% (252-256) bit + 5%% (248-252) bit\n");
						printf("  Base Key     : Randomly changes %d start Private keys every %llu,000,000,000 on the counter\n\n", nbThread, rKey);
					}
				}
				for (int i = 0; i < nbThread; i++) {
					gpucores = i;
					keys[i].Rand(256);
					rhex = keys;
					Int k(keys + i);
					k.Add((uint64_t)(groupSize / 2));
					p[i] = secp->ComputePublicKey(&k);
				}
			}
		}
	}
	else {
		Int tThreads;
		tThreads.SetInt32(nbThread);
		Int tRangeDiff(tRangeEnd);
		Int tRangeStart2(tRangeStart);
		Int tRangeEnd2(tRangeStart);

		tRangeDiff.Set(&tRangeEnd);
		tRangeDiff.Sub(&tRangeStart);
		razn = tRangeDiff;

		tRangeDiff.Div(&tThreads);

		int rangeShowThreasold = 3;
		int rangeShowCounter = 0;
		uint64_t nextt = 0;
		if (value777 > 1) {
			nextt = value777 / nbThread;
			tRangeStart2.Add(nextt);
		}
		if (next > 0) {
			if (display > 0) {
				printf("  Rotor info   : Save checkpoints every %d minutes. For continue range, run the bat file Rotor-Cuda_Continue.bat \n", next);
			}
		}
		gir.Set(&rangeDiff2);
		Int reh;
		uint64_t nextt99;
		nextt99 = value777 * 1;
		reh.Add(nextt99);
		gir.Sub(&reh);

		if (display > 0) {
			if (value777 > 1) {
				printf("\n  Rotor info   : Continuation... Divide the remaining range %s (%d bit) into GPU %d threads \n\n", gir.GetBase16().c_str(), gir.GetBitLength(), nbThread);
			}
			else {
				printf("\n  Rotor info   : Divide the range %s (%d bit) into GPU %d threads \n\n", rangeDiff2.GetBase16().c_str(), gir.GetBitLength(), nbThread);
			}
		}
		for (int i = 0; i < nbThread + 1; i++) {
			gpucores = i;
			tRangeEnd2.Set(&tRangeStart2);
			tRangeEnd2.Add(&tRangeDiff);

			keys[i].Set(&tRangeStart2);
			if (i == 0) {
				if (display > 0) {
					printf("  Thread 00000 : %s ->", keys[i].GetBase16().c_str());
				}
			}
			Int dobb;
			dobb.Set(&tRangeStart2);
			dobb.Add(&tRangeDiff);
			dobb.Sub(nextt);
			if (display > 0) {
				if (i == 0) {
					printf(" %s \n", dobb.GetBase16().c_str());
				}
				if (i == 1) {
					printf("  Thread 00001 : %s -> %s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
				if (i == 2) {
					printf("  Thread 00002 : %s -> %s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
				if (i == 3) {
					printf("  Thread 00003 : %s -> %s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
					printf("     ... \n");
				}
				if (i == nbThread - 2) {
					printf("  Thread %d : %s -> %s \n", i, tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
				if (i == nbThread - 1) {
					printf("  Thread %d : %s -> %s \n", i, tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
				if (i == nbThread) {
					printf("  Thread %d : %s -> %s \n\n", i, tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
			}
			tRangeStart2.Add(&tRangeDiff);
			Int k(keys + i);
			k.Add((uint64_t)(groupSize / 2));
			p[i] = secp->ComputePublicKey(&k);
		}
	}
}

void Rotor::FindKeyGPU(TH_PARAM * ph)
{
	bool ok = true;

#ifdef WITHGPU

	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;

	GPUEngine* g;
	switch (searchMode) {
	case (int)SEARCH_MODE_MA:
	case (int)SEARCH_MODE_MX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			BLOOM_N, bloom->get_bits(), bloom->get_hashes(), bloom->get_bf(), DATA, TOTAL_COUNT, (rKey != 0));
		break;
	case (int)SEARCH_MODE_SA:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			hash160Keccak, (rKey != 0));
		break;
	case (int)SEARCH_MODE_SX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			xpoint, (rKey != 0));
		break;
	default:
		printf("  Invalid search mode format!");
		return;
		break;
	}

	int nbThread = g->GetNbThread();
	Point* p = new Point[nbThread];
	Int* keys = new Int[nbThread];
	std::vector<ITEM> found;

	printf("  GPU          : %s\n", g->deviceName.c_str());

	counters[thId] = 0;

	getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
	ok = g->SetKeys(p);

	ph->hasStarted = true;
	ph->rKeyRequest = false;

	while (ok && !endOfSearch) {

		if (ph->rKeyRequest) {
			getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
			ok = g->SetKeys(p);
			ph->rKeyRequest = false;
		}

		switch (searchMode) {
		case (int)SEARCH_MODE_MA:
			ok = g->LaunchSEARCH_MODE_MA(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				if (coinType == COIN_BTC) {
					std::string addr = secp->GetAddress(it.mode, it.hash);
					if (checkPrivKey(addr, keys[it.thId], it.incr, it.mode)) {
						nbFoundKey++;
					}
				}
				else {
					std::string addr = secp->GetAddressETH(it.hash);
					if (checkPrivKeyETH(addr, keys[it.thId], it.incr)) {
						nbFoundKey++;
					}
				}
			}
			break;
		case (int)SEARCH_MODE_MX:
			ok = g->LaunchSEARCH_MODE_MX(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				if (checkPrivKeyX(keys[it.thId], it.incr, it.mode)) {
					nbFoundKey++;
				}
			}
			break;
		case (int)SEARCH_MODE_SA:
			ok = g->LaunchSEARCH_MODE_SA(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				if (coinType == COIN_BTC) {
					std::string addr = secp->GetAddress(it.mode, it.hash);
					if (checkPrivKey(addr, keys[it.thId], it.incr, it.mode)) {
						nbFoundKey++;
					}
				}
				else {
					std::string addr = secp->GetAddressETH(it.hash);
					if (checkPrivKeyETH(addr, keys[it.thId], it.incr)) {
						nbFoundKey++;
					}
				}
			}
			break;
		case (int)SEARCH_MODE_SX:
			ok = g->LaunchSEARCH_MODE_SX(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				if (checkPrivKeyX(keys[it.thId], it.incr, it.mode)) {
					nbFoundKey++;
				}
			}
			break;
		default:
			break;
		}

		if (ok) {
			for (int i = 0; i < nbThread; i++) {
				keys[i].Add((uint64_t)STEP_SIZE);
			}
			counters[thId] += (uint64_t)(STEP_SIZE)*nbThread;
		}
	}

	delete[] keys;
	delete[] p;
	delete g;

#else
	ph->hasStarted = true;
	printf("  GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif

	ph->isRunning = false;
}

// ----------------------------------------------------------------------------

bool Rotor::isAlive(TH_PARAM * p)
{
	bool isAlive = true;
	for (int i = 0; i < nbGPUThread; i++)
		isAlive = isAlive && p[i].isRunning;
	return isAlive;
}

// ----------------------------------------------------------------------------

bool Rotor::hasStarted(TH_PARAM * p)
{
	bool hasStarted = true;
	for (int i = 0; i < nbGPUThread; i++)
		hasStarted = hasStarted && p[i].hasStarted;
	return hasStarted;
}

// ----------------------------------------------------------------------------

uint64_t Rotor::getGPUCount()
{
	uint64_t count = 0;
	if (value777 > 1000000) {
		count = value777;
	}
	for (int i = 0; i < nbGPUThread; i++)
		count += counters[i];
	return count;
}

// ----------------------------------------------------------------------------

void Rotor::rKeyRequest(TH_PARAM * p) {
	for (int i = 0; i < nbGPUThread; i++)
		p[i].rKeyRequest = true;
}
// ----------------------------------------------------------------------------

void Rotor::SetupRanges(uint32_t totalThreads)
{
	Int threads;
	threads.SetInt32(totalThreads);
	rangeDiff.Set(&rangeEnd);
	rangeDiff.Sub(&rangeStart);
	rangeDiff.Div(&threads);
}

// ----------------------------------------------------------------------------

void Rotor::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{
	double t0;
	double t1;
	endOfSearch = false;
	nbGPUThread = (useGpu ? (int)gpuId.size() : 0);
	nbFoundKey = 0;

	SetupRanges(nbGPUThread);

	memset(counters, 0, sizeof(counters));

	if (!useGpu)
		printf("\n");

	TH_PARAM* params = (TH_PARAM*)malloc(nbGPUThread * sizeof(TH_PARAM));
	memset(params, 0, nbGPUThread * sizeof(TH_PARAM));

	// Launch GPU threads
	for (int i = 0; i < nbGPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = 0x80L + i;
		params[i].isRunning = true;
		params[i].gpuId = gpuId[i];
		params[i].gridSizeX = gridSize[2 * i];
		params[i].gridSizeY = gridSize[2 * i + 1];
		if (rKey > 0) {
			Int kubik;
			params[i].rangeStart.Set(&kubik);
		}
		else {
			params[i].rangeStart.Set(&rangeStart);
			rangeStart.Add(&rangeDiff);
			params[i].rangeEnd.Set(&rangeStart);
		}
#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyGPU, (void*)(params + i), 0, &thread_id);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyGPU, (void*)(params + i));
#endif
	}

#ifndef WIN64
	setvbuf(stdout, NULL, _IONBF, 0);
#endif
	printf("\n");

	uint64_t lastCount = 0;
	uint64_t gpuCount = 0;
	uint64_t lastGPUCount = 0;

#define FILTER_SIZE 8
	double lastGpukeyRate[FILTER_SIZE];
	uint32_t filterPos = 0;

	double gpuKeyRate = 0.0;
	char timeStr[256];

	memset(lastGpukeyRate, 0, sizeof(lastGpukeyRate));

	while (!hasStarted(params)) {
		Timer::SleepMillis(500);
	}

	Timer::Init();
	t0 = Timer::get_tick();
	startTime = t0;
	Int p100;
	Int ICount;
	p100.SetInt32(100);
	double completedPerc = 0;
	uint64_t rKeyCount = 0;
	while (isAlive(params)) {

		int delay = 1000;
		while (isAlive(params) && delay > 0) {
			Timer::SleepMillis(500);
			delay -= 500;
		}

		gpuCount = getGPUCount();
		uint64_t count = gpuCount;
		ICount.SetInt64(count);
		int completedBits = ICount.GetBitLength();
		if (rKey <= 0) {
			completedPerc = CalcPercantage(ICount, rangeStart, rangeDiff2);
		}
		minuty++;

		t1 = Timer::get_tick();
		gpuKeyRate = (double)(gpuCount - lastGPUCount) / (t1 - t0);
		lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
		filterPos++;

		double avgGpuKeyRate = 0.0;
		uint32_t nbSample;
		for (nbSample = 0; (nbSample < FILTER_SIZE) && (nbSample < filterPos); nbSample++) {
			avgGpuKeyRate += lastGpukeyRate[nbSample];
		}
		avgGpuKeyRate /= (double)(nbSample);

		zhdat++;

		unsigned long long int years88, days88, hours88, minutes88, seconds88;

		// (Keep only GPU-related display)
		if (avgGpuKeyRate > 1000000000) {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] %s [F: %d] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
					toTimeStr(t1, timeStr),
					rhex.GetBase16().c_str(),
					nbFoundKey,
					completedPerc,
					avgGpuKeyRate / 1000000000.0,
					formatThousands(count).c_str());
			}
		}
		else {
			if (isAlive(params)) {
				memset(timeStr, '\0', 256);
				printf("\r  [%s] %s [F: %d] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]  ",
					toTimeStr(t1, timeStr),
					rhex.GetBase16().c_str(),
					nbFoundKey,
					completedPerc,
					avgGpuKeyRate / 1000000.0,
					formatThousands(count).c_str());
			}
		}

		if (rKey > 0) {
			if ((count - lastrKey) > (1000000000 * rKey)) {
				rKeyRequest(params);
				lastrKey = count;
				rKeyCount++;
				rKeyCount2 += rKeyCount;
			}
		}
		lastCount = count;
		lastGPUCount = gpuCount;
		t0 = t1;
		if (should_exit || nbFoundKey >= targetCounter || completedPerc > 100.5)
			endOfSearch = true;
	}

	free(params);
}

// ----------------------------------------------------------------------------

std::string Rotor::GetHex(std::vector<unsigned char> &buffer)
{
	std::string ret;

	char tmp[128];
	for (int i = 0; i < (int)buffer.size(); i++) {
		sprintf(tmp, "%02X", buffer[i]);
		ret.append(tmp);
	}
	return ret;
}

// ----------------------------------------------------------------------------

int Rotor::CheckBloomBinary(const uint8_t * _xx, uint32_t K_LENGTH)
{
	if (bloom->check(_xx, K_LENGTH) > 0) {
		uint8_t* temp_read;
		uint64_t half, min, max, current;
		int64_t rcmp;
		int32_t r = 0;
		min = 0;
		current = 0;
		max = TOTAL_COUNT;
		half = TOTAL_COUNT;
		while (!r && half >= 1) {
			half = (max - min) / 2;
			temp_read = DATA + ((current + half) * K_LENGTH);
			rcmp = memcmp(_xx, temp_read, K_LENGTH);
			if (rcmp == 0) {
				r = 1;
			}
			else {
				if (rcmp < 0) {
					max = (max - half);
				}
				else {
					min = (min + half);
				}
				current = min;
			}
		}
		return r;
	}
	return 0;
}

// ----------------------------------------------------------------------------

bool Rotor::MatchHash(uint32_t * _h)
{
	if (_h[0] == hash160Keccak[0] &&
		_h[1] == hash160Keccak[1] &&
		_h[2] == hash160Keccak[2] &&
		_h[3] == hash160Keccak[3] &&
		_h[4] == hash160Keccak[4]) {
		return true;
	}
	else {
		return false;
	}
}

// ----------------------------------------------------------------------------

bool Rotor::MatchXPoint(uint32_t * _h)
{
	if (_h[0] == xpoint[0] &&
		_h[1] == xpoint[1] &&
		_h[2] == xpoint[2] &&
		_h[3] == xpoint[3] &&
		_h[4] == xpoint[4] &&
		_h[5] == xpoint[5] &&
		_h[6] == xpoint[6] &&
		_h[7] == xpoint[7]) {
		return true;
	}
	else {
		return false;
	}
}

// ----------------------------------------------------------------------------

std::string Rotor::formatThousands(uint64_t x)
{
	char buf[32] = "";

	sprintf(buf, "%llu", x);

	std::string s(buf);

	int len = (int)s.length();

	int numCommas = (len - 1) / 3;

	if (numCommas == 0) {
		return s;
	}

	std::string result = "";

	int count = ((len % 3) == 0) ? 0 : (3 - (len % 3));

	for (int i = 0; i < len; i++) {
		result += s[i];

		if (count++ == 2 && i < len - 1) {
			result += ",";
			count = 0;
		}
	}
	return result;
}

// ----------------------------------------------------------------------------

char* Rotor::toTimeStr(int sec, char* timeStr)
{
	int h, m, s;
	h = (sec / 3600);
	m = (sec - (3600 * h)) / 60;
	s = (sec - (3600 * h) - (m * 60));
	sprintf(timeStr, "%0*d:%0*d:%0*d", 2, h, 2, m, 2, s);
	return (char*)timeStr;
}
