/*
Develop by Alberto
email: albertobsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include <fcntl.h>
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "oldbloom/oldbloom.h"
#include "bloom/bloom.h"
#include "sha3/sha3.h"
#include "util.h"
#include <thread>
#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"
#include <mutex>
#include "hash/sha256.h"
#include "hash/ripemd160.h"
#include <stdexcept>
#include <iostream>
#include <random>
#include <chrono>
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#include <linux/random.h>

#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2
#define CRYPTO_ALL 3

#define MODE_XPOINT 0
#define MODE_ADDRESS 1
#define MODE_BSGS 2
#define MODE_RMD160 3
#define MODE_PUB2RMD 4
#define MODE_MINIKEYS 5
#define MODE_VANITY 6

#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2

#define BUFFER_SIZE 2048 // Tamanho do buffer para otimizar gravação em arquivo
static char key_buffer[BUFFER_SIZE];
size_t buffer_index = 0;
char global_public_key[131]; // Global variable to store the public key
uint32_t  THREADBPWORKLOAD = 1048576;

struct checksumsha256	{
	char data[32];
	char backup[32];
};

struct bsgs_xvalue	{
	uint8_t value[6];
	uint64_t index;
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};

struct bPload	{
	uint32_t threadid;
	uint64_t from;
	uint64_t to;
	uint64_t counter;
	uint64_t workload;
	uint32_t aux;
	uint32_t finished;
};

struct publickey {
    uint8_t parity;
    union {
        uint8_t data8[32];
        uint32_t data32[8];
        uint64_t data64[4];
    } X;
} __attribute__((__packed__));

const char *Ccoinbuffer_default = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

char *Ccoinbuffer = (char*) Ccoinbuffer_default;
char *str_baseminikey = NULL;
char *raw_baseminikey = NULL;
char *minikeyN = NULL;
int minikey_n_limit;
	
const char *version = "0.2.230519 Satoshi Quest";

#define CPU_GRP_SIZE 1024

std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

void menu();
void init_generator();

int searchbinary(struct address_value *buffer,char *data,int64_t array_length);
void sleep_ms(int milliseconds);

void _sort(struct address_value *arr,int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n);
void _swap(struct address_value *a,struct address_value *b);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value	*arr, int64_t n);
void _heapify(struct address_value *arr, int64_t n, int64_t i);

void bsgs_sort(struct bsgs_xvalue *arr,int64_t n);
void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n);
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b);
void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i);
int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n);

int bsgs_searchbinary(struct bsgs_xvalue *arr,char *data,int64_t array_length,uint64_t *r_value);
int bsgs_secondcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey);
int bsgs_thirdcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey);

void sha256sse_22(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);
void sha256sse_23(uint8_t *src0, uint8_t *src1, uint8_t *src2, uint8_t *src3, uint8_t *dst0, uint8_t *dst1, uint8_t *dst2, uint8_t *dst3);

bool vanityrmdmatch(unsigned char *rmdhash);
void writevanitykey(bool compress,Int *key);
int addvanity(char *target);
int minimum_same_bytes(unsigned char* A,unsigned char* B, int length);

void writekey(bool compressed,Int *key);
void writekeyeth(Int *key);

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);

bool isBase58(char c);
bool isValidBase58String(char *str);

bool readFileAddress(char *fileName);
bool readFileVanity(char *fileName);
bool forceReadFileAddress(char *fileName);
bool forceReadFileAddressEth(char *fileName);
bool forceReadFileXPoint(char *fileName);
bool processOneVanity();

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom);

void writeFileIfNeeded(const char *fileName);

void calcualteindex(int i,Int *key);
// Funções de threads utilizando C++11
void* thread_process_bsgs(void* vargp);
void* thread_bPload(void* vargp);
void* thread_bPload_2blooms(void* vargp);

char *pubkeytopubaddress(char *pkey,int length);
void pubkeytopubaddress_dst(char *pkey,int length,char *dst);
void rmd160toaddress_dst(char *rmd,char *dst);
void set_minikey(char *buffer,char *rawbuffer,int length);
bool increment_minikey_index(char *buffer,char *rawbuffer,int index);
void increment_minikey_N(char *rawbuffer);
	
void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst);
void generate_binaddress_eth(Point &publickey,unsigned char *dst_address);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *bsgs_modes[5] = {"sequential","backward","both","random","dance"};
const char *modes[7] = {"xpoint","address","bsgs","rmd160","pub2rmd","minikeys","vanity"};
const char *cryptos[3] = {"btc","eth","all"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_fileName = "addresses.txt";
std::mutex write_keys, write_random, bsgs_thread;
std::mutex* bPload_mutex = nullptr;
std::thread* tid = nullptr;

uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;
uint64_t THREADCYCLES = 0;
uint64_t THREADCOUNTER = 0;
uint64_t FINISHED_ITEMS = 0;
uint64_t OLDFINISHED_ITEMS = -1;

uint8_t byte_encode_crypto = 0x00;		/* Bitcoin  */


int vanity_rmd_targets = 0;
int vanity_rmd_total = 0;
int *vanity_rmd_limits = NULL;
uint8_t ***vanity_rmd_limit_values_A = NULL,***vanity_rmd_limit_values_B = NULL;
int vanity_rmd_minimun_bytes_check_length = 999999;
char **vanity_address_targets = NULL;
struct bloom *vanity_bloom = NULL;

struct bloom bloom;

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;
uint64_t u64range;

Int OUTPUTSECONDS;

int FLAGSKIPCHECKSUM = 0;
int FLAGENDOMORPHISM = 0;

int FLAGBLOOMMULTIPLIER = 1;
int FLAGVANITY = 0;
int FLAGBASEMINIKEY = 0;
int FLAGBSGSMODE = 0;
int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int FLAGMATRIX = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

int FLAGSAVEREADFILE = 0;
int FLAGREADEDFILE1 = 0;
int FLAGREADEDFILE2 = 0;
int FLAGREADEDFILE3 = 0;
int FLAGREADEDFILE4 = 0;
int FLAGUPDATEFILE1 = 0;


int FLAGSTRIDE = 0;
int FLAGSEARCH = 2;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGMODE = MODE_ADDRESS;
int FLAGCRYPTO = 0;
int FLAGRAWDATA	= 0;
int FLAGRANDOM = 0;
int FLAG_N = 0;
int FLAGPRECALCUTED_P_FILE = 0;

int bitrange;
char *str_N;
char *range_start;
char *range_end;
char *str_stride;
Int stride;

uint64_t BSGS_XVALUE_RAM = 6;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;

/*
BSGS Variables
*/
int *bsgs_found;
std::vector<Point> OriginalPointsBSGS;
bool *OriginalPointsBSGScompressed;

uint64_t bytes;
char checksum[32],checksum_backup[32];
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;
struct address_value *addressTable;

struct oldbloom oldbloom_bP;

struct bloom *bloom_bP;
struct bloom *bloom_bPx2nd; //2nd Bloom filter check
struct bloom *bloom_bPx3rd; //3rd Bloom filter check

struct checksumsha256 *bloom_bP_checksums;
struct checksumsha256 *bloom_bPx2nd_checksums;
struct checksumsha256 *bloom_bPx3rd_checksums;

const int MAX_INDEX = 256;
std::vector<std::mutex> bloom_bP_mutex(MAX_INDEX);
std::vector<std::mutex> bloom_bPx2nd_mutex(MAX_INDEX);
std::vector<std::mutex> bloom_bPx3rd_mutex(MAX_INDEX);

uint64_t bloom_bP_totalbytes = 0;
uint64_t bloom_bP2_totalbytes = 0;
uint64_t bloom_bP3_totalbytes = 0;
uint64_t bsgs_m = 4194304;
uint64_t bsgs_m2;
uint64_t bsgs_m3;
uint64_t bsgs_aux;
uint32_t bsgs_point_number;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];




Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_N_double;
Int BSGS_M;					//M is squareroot(N)
Int BSGS_M_double;
Int BSGS_M2;				//M2 is M/32
Int BSGS_M2_double;			//M2_double is M2 * 2
Int BSGS_M3;				//M3 is M2/32
Int BSGS_M3_double;			//M3_double is M3 * 2

Int ONE;
Int ZERO;
Int MPZAUX;

Point BSGS_P;			//Original P is actually G, but this P value change over time for calculations
Point BSGS_MP;			//MP values this is m * P
Point BSGS_MP2;			//MP2 values this is m2 * P
Point BSGS_MP3;			//MP3 values this is m3 * P

Point BSGS_MP_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP2_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP3_double;			//MP3 values this is m3 * P * 2


std::vector<Point> BSGS_AMP2;
std::vector<Point> BSGS_AMP3;

Point point_temp,point_temp2;	//Temp value for some process

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;

Int lambda,lambda2,beta,beta2;

Secp256K1 *secp;

// Função para inicializar o RNG com uma semente segura e multiplataforma
void initializeRNG() {
    unsigned long seedValue;

    // Usando std::random_device, que utiliza um gerador seguro se disponível
    std::random_device rd;

    if (rd.entropy() > 0) {
        // std::random_device fornece uma semente de alta qualidade e segura
        seedValue = rd();
    } else {
        // Fallback para uma semente baseada no tempo caso std::random_device não esteja disponível
        seedValue = std::chrono::system_clock::now().time_since_epoch().count() ^
                    std::chrono::steady_clock::now().time_since_epoch().count();
    }

    // Definir semente para o gerador
    rseed(seedValue);
}

int main(int argc, char **argv)	{

	/**	INICIALIZANDO FUNÇÕES **/
	initializeRNG();

	char buffer[2048];
	char rawvalue[32];
	struct tothread *tt;	//tothread
	Tokenizer t,tokenizerbsgs;	//tokenizer
	char *fileName = NULL;
	char *hextemp = NULL;
	char *aux = NULL;
	char *aux2 = NULL;
	char *pointx_str = NULL;
	char *pointy_str = NULL;
	char *str_seconds = NULL;
	char *str_total = NULL;
	char *str_pretotal = NULL;
	char *str_divpretotal = NULL;
	char *bf_ptr = NULL;
	char *bPload_threads_available;
	FILE *fd,*fd_aux1,*fd_aux2,*fd_aux3;
	uint64_t i,BASE,PERTHREAD_R,itemsbloom,itemsbloom2,itemsbloom3;
	uint32_t finished;
	int readed,continue_flag,check_flag,c,salir,index_value,j;
	Int total,pretotal,debugcount_mpz,seconds,div_pretotal,int_aux,int_r,int_q,int58;
	struct bPload *bPload_temp_ptr;
	size_t rsize;
	
	std::mutex write_keys, write_random, bsgs_thread;
	int s;
	srand(time(NULL));

	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(30);
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);
	
	int randomNumber = std::rand();  // Exemplo de número aleatório
    std::cout << "Número aleatório: " << randomNumber << std::endl;	
	
	printf("[+] Version %s, developed by AlbertoBSD\n",version);

	while ((c = getopt(argc, argv, "deh6MqRSB:b:c:C:E:f:I:k:l:m:N:n:p:r:s:t:v:G:8:z:")) != -1) {
		switch(c) {
			case 'h':
				menu();
			break;
			case '6':
				FLAGSKIPCHECKSUM = 1;
				fprintf(stderr,"[W] Skipping checksums on files\n");
			break;
			case 'B':
				index_value = indexOf(optarg,bsgs_modes,5);
				if(index_value >= 0 && index_value <= 4)	{
					FLAGBSGSMODE = index_value;
					printf("[+] BSGS mode %s\n",optarg);
				}
				else	{
					fprintf(stderr,"[W] Ignoring unknow bsgs mode %s\n",optarg);
				}
			break;
			case 'b':
				bitrange = strtol(optarg,NULL,10);
				if(bitrange > 0 && bitrange <=256 )	{
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange-1);
					bit_range_str_min = MPZAUX.GetBase16();
					checkpointer((void *)bit_range_str_min,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange);
					if(MPZAUX.IsGreater(&secp->order))	{
						MPZAUX.Set(&secp->order);
					}
					bit_range_str_max = MPZAUX.GetBase16();
					checkpointer((void *)bit_range_str_max,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
					FLAGBITRANGE = 1;
				}
				else	{
					fprintf(stderr,"[E] invalid bits param: %s.\n",optarg);
				}
			break;
			case 'c':
				index_value = indexOf(optarg,cryptos,3);
				switch(index_value) {
					case 0: //btc
						FLAGCRYPTO = CRYPTO_BTC;
					break;
					case 1: //eth
						FLAGCRYPTO = CRYPTO_ETH;
						printf("[+] Setting search for ETH adddress.\n");
					break;
					/*
					case 2: //all
						FLAGCRYPTO = CRYPTO_ALL;
					break;
					*/
					default:
						FLAGCRYPTO = CRYPTO_NONE;
						fprintf(stderr,"[E] Unknow crypto value %s\n",optarg);
						exit(EXIT_FAILURE);
					break;
				}
			break;
			case 'd':
				FLAGDEBUG = 1;
				printf("[+] Flag DEBUG enabled\n");
			break;
			case 'f':
				FLAGFILE = 1;
				fileName = optarg;
			break;
			case 'I':
				FLAGSTRIDE = 1;
				str_stride = optarg;
			break;
			case 'k':
				KFACTOR = (int)strtol(optarg,NULL,10);
				if(KFACTOR <= 0)	{
					KFACTOR = 1;
				}
				printf("[+] K factor %i\n",KFACTOR);
			break;
			case 'M':
				FLAGMATRIX = 1;
				printf("[+] Matrix screen\n");
			break;
			case 'm':
				switch(indexOf(optarg,modes,7)) {
					case MODE_BSGS:
						FLAGMODE = MODE_BSGS;
						//printf("[+] Mode BSGS\n");
					break;
					default:
						fprintf(stderr,"[E] Unknow mode value %s\n",optarg);
						exit(EXIT_FAILURE);
					break;
				}
			break;
			case 'n':
				FLAG_N = 1;
				str_N = optarg;
			break;
			case 'q':
				FLAGQUIET	= 1;
				printf("[+] Quiet thread output\n");
			break;
			case 'R':
				printf("[+] Random mode\n");
				FLAGRANDOM = 1;
				FLAGBSGSMODE =  3;
			break;
			case 'r':
				if(optarg != NULL)	{
					stringtokenizer(optarg,&t);
					switch(t.n)	{
						case 1:
							range_start = nextToken(&t);
							if(isValidHex(range_start)) {
								FLAGRANGE = 1;
								range_end = secp->order.GetBase16();
							}
							else	{
								fprintf(stderr,"[E] Invalid hexstring : %s.\n",range_start);
							}
						break;
						case 2:
							range_start = nextToken(&t);
							range_end	 = nextToken(&t);
							if(isValidHex(range_start) && isValidHex(range_end)) {
									FLAGRANGE = 1;
							}
							else	{
								if(isValidHex(range_start)) {
									fprintf(stderr,"[E] Invalid hexstring : %s\n",range_start);
								}
								else	{
									fprintf(stderr,"[E] Invalid hexstring : %s\n",range_end);
								}
							}
						break;
						default:
							printf("[E] Unknow number of Range Params: %i\n",t.n);
						break;
					}
				}
			break;
			case 's':
				OUTPUTSECONDS.SetBase10(optarg);
				if(OUTPUTSECONDS.IsLower(&ZERO))	{
					OUTPUTSECONDS.SetInt32(30);
				}
				if(OUTPUTSECONDS.IsZero())	{
					printf("[+] Turn off stats output\n");
				}
				else	{
					hextemp = OUTPUTSECONDS.GetBase10();
					printf("[+] Stats output every %s seconds\n",hextemp);
					free(hextemp);
				}
			break;
			case 'S':
				FLAGSAVEREADFILE = 1;
			break;
			case 't':
				NTHREADS = strtol(optarg,NULL,10);
				if(NTHREADS <= 0)	{
					NTHREADS = 1;
				}
				printf((NTHREADS > 1) ? "[+] Threads : %u\n": "[+] Thread : %u\n",NTHREADS);
			break;
			case 'z':
				FLAGBLOOMMULTIPLIER= strtol(optarg,NULL,10);
				if(FLAGBLOOMMULTIPLIER <= 0)	{
					FLAGBLOOMMULTIPLIER = 1;
				}
				printf("[+] Bloom Size Multiplier %i\n",FLAGBLOOMMULTIPLIER);
			break;
			default:
				fprintf(stderr,"[E] Unknow opcion -%c\n",c);
				exit(EXIT_FAILURE);
			break;
		}
	}
	init_generator();
	if(FLAGMODE == MODE_BSGS )	{
		printf("[+] Mode BSGS %s\n",bsgs_modes[FLAGBSGSMODE]);
	}
	
	if(FLAGFILE == 0) {
		fileName =(char*) default_fileName;
	}
	if(FLAGRANGE) {
		n_range_start.SetBase16(range_start);
		if(n_range_start.IsZero())	{
			n_range_start.AddOne();
		}
		n_range_end.SetBase16(range_end);
		if(n_range_start.IsEqual(&n_range_end) == false ) {
			if(  n_range_start.IsLower(&secp->order) &&  n_range_end.IsLowerOrEqual(&secp->order) )	{
				if( n_range_start.IsGreater(&n_range_end)) {
					fprintf(stderr,"[W] Opps, start range can't be great than end range. Swapping them\n");
					n_range_aux.Set(&n_range_start);
					n_range_start.Set(&n_range_end);
					n_range_end.Set(&n_range_aux);
				}
				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
			}
			else	{
				fprintf(stderr,"[E] Start and End range can't be great than N\nFallback to random mode!\n");
				FLAGRANGE = 0;
			}
		}
		else	{
			fprintf(stderr,"[E] Start and End range can't be the same\nFallback to random mode!\n");
			FLAGRANGE = 0;
		}
	}
	N = 0;
	
	if(FLAGMODE == MODE_BSGS )	{
		printf("[+] Opening file %s\n",fileName);
		fd = fopen(fileName,"rb");
		if(fd == NULL)	{
			fprintf(stderr,"[E] Can't open file %s\n",fileName);
			exit(EXIT_FAILURE);
		}
		aux = (char*) malloc(1024);
		checkpointer((void *)aux,__FILE__,"malloc","aux" ,__LINE__ - 1);
		while(!feof(fd))	{
			if(fgets(aux,1022,fd) == aux)	{
				trim(aux," \t\n\r");
				if(strlen(aux) >= 128)	{	//Length of a full address in hexadecimal without 04
						N++;
				}else	{
					if(strlen(aux) >= 66)	{
						N++;
					}
				}
			}
		}
		if(N == 0)	{
			fprintf(stderr,"[E] There is no valid data in the file\n");
			exit(EXIT_FAILURE);
		}
		bsgs_found = (int*) calloc(N,sizeof(int));
		checkpointer((void *)bsgs_found,__FILE__,"calloc","bsgs_found" ,__LINE__ -1 );
		OriginalPointsBSGS.reserve(N);
		OriginalPointsBSGScompressed = (bool*) malloc(N*sizeof(bool));
		checkpointer((void *)OriginalPointsBSGScompressed,__FILE__,"malloc","OriginalPointsBSGScompressed" ,__LINE__ -1 );
		pointx_str = (char*) malloc(65);
		checkpointer((void *)pointx_str,__FILE__,"malloc","pointx_str" ,__LINE__ -1 );
		pointy_str = (char*) malloc(65);
		checkpointer((void *)pointy_str,__FILE__,"malloc","pointy_str" ,__LINE__ -1 );
		fseek(fd,0,SEEK_SET);
		i = 0;
		while(!feof(fd))	{
			if(fgets(aux,1022,fd) == aux)	{
				trim(aux," \t\n\r");
				if(strlen(aux) >= 66)	{
					stringtokenizer(aux,&tokenizerbsgs);
					aux2 = nextToken(&tokenizerbsgs);
					strncpy(global_public_key, aux2, 130);
					global_public_key[130] = '\0';
					memset(pointx_str,0,65);
					memset(pointy_str,0,65);
					switch(strlen(aux2))	{
						case 66:	//Compress

							if(secp->ParsePublicKeyHex(aux2,OriginalPointsBSGS[i],OriginalPointsBSGScompressed[i]))	{
								i++;
							}
							else	{
								N--;
							}

						break;
						case 130:	//With the 04

							if(secp->ParsePublicKeyHex(aux2,OriginalPointsBSGS[i],OriginalPointsBSGScompressed[i]))	{
								i++;
							}
							else	{
								N--;
							}

						break;
						default:
							printf("Invalid length: %s\n",aux2);
							N--;
						break;
					}
					freetokenizer(&tokenizerbsgs);
				}
			}
		}
		fclose(fd);

		bsgs_point_number = N;
		if(bsgs_point_number > 0)	{
			printf("[+] Added %u points from file\n",bsgs_point_number);
		}
		else	{
			fprintf(stderr,"[E] The file don't have any valid publickeys\n");
			exit(EXIT_FAILURE);
		}
		BSGS_N.SetInt32(0);
		BSGS_M.SetInt32(0);
		

		BSGS_M.SetInt64(bsgs_m);


		if(FLAG_N)	{	//Custom N by the -n param
						
			/* Here we need to validate if the given string is a valid hexadecimal number or a base 10 number*/
			
			/* Now the conversion*/
			if(str_N[0] == '0' && str_N[1] == 'x' )	{	/*We expected a hexadecimal value after 0x  -> str_N +2 */
				BSGS_N.SetBase16((char*)(str_N+2));
			}
			else	{
				BSGS_N.SetBase10(str_N);
			}
			
		}
		else	{	//Default N
			BSGS_N.SetInt64((uint64_t)0x100000000000);
		}

		if(BSGS_N.HasSqrt())	{	//If the root is exact
			BSGS_M.Set(&BSGS_N);
			BSGS_M.ModSqrt();
		}
		else	{
			fprintf(stderr,"[E] -n param doesn't have exact square root\n");
			exit(EXIT_FAILURE);
		}

		BSGS_AUX.Set(&BSGS_M);
		BSGS_AUX.Mod(&BSGS_GROUP_SIZE);

		if(!BSGS_AUX.IsZero()){ //If M is not divisible by  BSGS_GROUP_SIZE (1024) 
			hextemp = BSGS_GROUP_SIZE.GetBase10();
			fprintf(stderr,"[E] M value is not divisible by %s\n",hextemp);
			exit(EXIT_FAILURE);
		}

		bsgs_m = BSGS_M.GetInt64();

		if(FLAGRANGE || FLAGBITRANGE)	{
			if(FLAGBITRANGE)	{	// Bit Range
				n_range_start.SetBase16(bit_range_str_min);
				n_range_end.SetBase16(bit_range_str_max);

				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
				printf("[+] Bit Range %i\n",bitrange);
				printf("[+] -- from : 0x%s\n",bit_range_str_min);
				printf("[+] -- to   : 0x%s\n",bit_range_str_max);
			}
			else	{
				printf("[+] Range \n");
				printf("[+] -- from : 0x%s\n",range_start);
				printf("[+] -- to   : 0x%s\n",range_end);
			}
		}
		else	{	//Random start

			n_range_start.SetInt32(1);
			n_range_end.Set(&secp->order);
			n_range_diff.Rand(&n_range_start,&n_range_end);
			n_range_start.Set(&n_range_diff);
		}
		BSGS_CURRENT.Set(&n_range_start);


		if(n_range_diff.IsLower(&BSGS_N) )	{
			fprintf(stderr,"[E] the given range is small\n");
			exit(EXIT_FAILURE);
		}

		BSGS_M.Mult((uint64_t)KFACTOR);
		BSGS_AUX.SetInt32(32);
		BSGS_R.Set(&BSGS_M);
		BSGS_R.Mod(&BSGS_AUX);
		BSGS_M2.Set(&BSGS_M);
		BSGS_M2.Div(&BSGS_AUX);

		if(!BSGS_R.IsZero())	{ /* If BSGS_M modulo 32 is not 0*/
			BSGS_M2.AddOne();
		}
		
		BSGS_M_double.SetInt32(2);
		BSGS_M_double.Mult(&BSGS_M);
		
		
		BSGS_M2_double.SetInt32(2);
		BSGS_M2_double.Mult(&BSGS_M2);
		
		BSGS_R.Set(&BSGS_M2);
		BSGS_R.Mod(&BSGS_AUX);
		
		BSGS_M3.Set(&BSGS_M2);
		BSGS_M3.Div(&BSGS_AUX);
		
		if(!BSGS_R.IsZero())	{ /* If BSGS_M2 modulo 32 is not 0*/
			BSGS_M3.AddOne();
		}
		
		BSGS_M3_double.SetInt32(2);
		BSGS_M3_double.Mult(&BSGS_M3);
		
		bsgs_m2 =  BSGS_M2.GetInt64();
		bsgs_m3 =  BSGS_M3.GetInt64();
		
		BSGS_AUX.Set(&BSGS_N);
		BSGS_AUX.Div(&BSGS_M);
		
		BSGS_R.Set(&BSGS_N);
		BSGS_R.Mod(&BSGS_M);

		if(!BSGS_R.IsZero())	{ /* if BSGS_N modulo BSGS_M is not 0*/
			BSGS_N.Set(&BSGS_M);
			BSGS_N.Mult(&BSGS_AUX);
		}

		bsgs_m = BSGS_M.GetInt64();
		bsgs_aux = BSGS_AUX.GetInt64();
		
		
		BSGS_N_double.SetInt32(2);
		BSGS_N_double.Mult(&BSGS_N);

		
		hextemp = BSGS_N.GetBase16();
		printf("[+] N = 0x%s\n",hextemp);
		free(hextemp);
		if(((uint64_t)(bsgs_m/256)) > 10000)	{
			itemsbloom = (uint64_t)(bsgs_m / 256);
			if(bsgs_m % 256 != 0 )	{
				itemsbloom++;
			}
		}
		else{
			itemsbloom = 1000;
		}
		
		if(((uint64_t)(bsgs_m2/256)) > 1000)	{
			itemsbloom2 = (uint64_t)(bsgs_m2 / 256);
			if(bsgs_m2 % 256 != 0)	{
				itemsbloom2++;
			}
		}
		else	{
			itemsbloom2 = 1000;
		}
		
		if(((uint64_t)(bsgs_m3/256)) > 1000)	{
			itemsbloom3 = (uint64_t)(bsgs_m3/256);
			if(bsgs_m3 % 256 != 0 )	{
				itemsbloom3++;
			}
		}
		else	{
			itemsbloom3 = 1000;
		}

		printf("[+] Bloom filter for 1 %" PRIu64 " elements ",bsgs_m);
		fflush(stdout);
		bloom_bP = (struct bloom*)calloc(256, sizeof(struct bloom));
		checkpointer((void *)bloom_bP,__FILE__,"calloc","bloom_bP" ,__LINE__ -1 );
		
		bloom_bP_checksums = (struct checksumsha256*)calloc(256, sizeof(struct checksumsha256));
		if (bloom_bP_checksums == NULL) {
			fprintf(stderr, "Error: Failed to allocate memory for bloom_bP_checksums.\n");
			exit(EXIT_FAILURE);
		}
		checkpointer((void *)bloom_bP_checksums,__FILE__,"calloc","bloom_bP_checksums" ,__LINE__ -1 );
		checkpointer((void*)bloom_bP_mutex.data(), __FILE__, "calloc", "bloom_bP_mutex", __LINE__ - 1);
		fflush(stdout);
		bloom_bP_totalbytes = 0;
		for(i=0; i< 256; i++)	{
			if(bloom_init2(&bloom_bP[i],itemsbloom,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init _ [%" PRIu64 "]\n",i);
				exit(EXIT_FAILURE);
			}
			bloom_bP_totalbytes += bloom_bP[i].bytes;
			//if(FLAGDEBUG) bloom_print(&bloom_bP[i]);
			
		}
		printf(": %.2f MB\n",(float)((float)(uint64_t)bloom_bP_totalbytes/(float)(uint64_t)1048576));

		
		printf("[+] Bloom filter for 2 %" PRIu64 " elements ",bsgs_m2);
		checkpointer(bloom_bPx2nd_mutex.data(), __FILE__, "calloc", "bloom_bPx2nd_mutex", __LINE__ - 1);
		fprintf(stderr, "TESTE  %.2f.\n", bsgs_m2);
		bloom_bPx2nd = (struct bloom*)calloc(256,sizeof(struct bloom));
		checkpointer((void *)bloom_bPx2nd,__FILE__,"calloc","bloom_bPx2nd" ,__LINE__ -1 );
		bloom_bPx2nd_checksums = (struct checksumsha256*) calloc(256,sizeof(struct checksumsha256));
		checkpointer((void *)bloom_bPx2nd_checksums,__FILE__,"calloc","bloom_bPx2nd_checksums" ,__LINE__ -1 );
		bloom_bP2_totalbytes = 0;
		for(i=0; i< 256; i++)	{
			if(bloom_init2(&bloom_bPx2nd[i],itemsbloom2,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init _ [%" PRIu64 "]\n",i);
				exit(EXIT_FAILURE);
			}
			bloom_bP2_totalbytes += bloom_bPx2nd[i].bytes;
			//if(FLAGDEBUG) bloom_print(&bloom_bPx2nd[i]);
		}
		
		printf(": %.2f MB\n",(float)((float)(uint64_t)bloom_bP2_totalbytes/(float)(uint64_t)1048576));
		checkpointer(static_cast<void*>(bloom_bPx3rd_mutex.data()), __FILE__, "calloc", "bloom_bPx3rd_mutex", __LINE__ - 1);

		bloom_bPx3rd = (struct bloom*)calloc(256, sizeof(struct bloom));
		checkpointer((void *)bloom_bPx3rd,__FILE__,"calloc","bloom_bPx3rd" ,__LINE__ -1 );
		bloom_bPx3rd_checksums = (struct checksumsha256*) calloc(256,sizeof(struct checksumsha256));
		checkpointer((void *)bloom_bPx3rd_checksums,__FILE__,"calloc","bloom_bPx3rd_checksums" ,__LINE__ -1 );
		
		printf("[+] Bloom filter for 3 %" PRIu64 " elements ",bsgs_m3);
		bloom_bP3_totalbytes = 0;
		for(i=0; i< 256; i++)	{
			if(bloom_init2(&bloom_bPx3rd[i],itemsbloom3,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init [%" PRIu64 "]\n",i);
				exit(EXIT_FAILURE);
			}
			bloom_bP3_totalbytes += bloom_bPx3rd[i].bytes;
			//if(FLAGDEBUG) bloom_print(&bloom_bPx3rd[i]);
		}
		printf(": %.2f MB\n",(float)((float)(uint64_t)bloom_bP3_totalbytes/(float)(uint64_t)1048576));

		BSGS_MP = secp->ComputePublicKey(&BSGS_M);
		BSGS_MP_double = secp->ComputePublicKey(&BSGS_M_double);
		BSGS_MP2 = secp->ComputePublicKey(&BSGS_M2);
		BSGS_MP2_double = secp->ComputePublicKey(&BSGS_M2_double);
		BSGS_MP3 = secp->ComputePublicKey(&BSGS_M3);
		BSGS_MP3_double = secp->ComputePublicKey(&BSGS_M3_double);
		
		BSGS_AMP2.reserve(32);
		BSGS_AMP3.reserve(32);
		GSn.reserve(CPU_GRP_SIZE/2);

		i= 0;


		/* New aMP table just to keep the same code of JLP */
		/* Auxiliar Points to speed up calculations for the main bloom filter check */
		Point bsP = secp->Negation(BSGS_MP_double);
		Point g = bsP;
		GSn[0] = g;

		g = secp->DoubleDirect(g);
		GSn[1] = g;
		
		for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
			g = secp->AddDirect(g,bsP);
			GSn[i] = g;
		}
		
		/* For next center point */
		_2GSn = secp->DoubleDirect(GSn[CPU_GRP_SIZE / 2 - 1]);
				
		i = 0;
		point_temp.Set(BSGS_MP2);
		BSGS_AMP2[0] = secp->Negation(point_temp);
		BSGS_AMP2[0].Reduce();
		point_temp.Set(BSGS_MP2_double);
		point_temp = secp->Negation(point_temp);
		point_temp.Reduce();
		
		for(i = 1; i < 32; i++)	{
			BSGS_AMP2[i] = secp->AddDirect(BSGS_AMP2[i-1],point_temp);
			BSGS_AMP2[i].Reduce();
		}
		
		i  = 0;
		point_temp.Set(BSGS_MP3);
		BSGS_AMP3[0] = secp->Negation(point_temp);
		BSGS_AMP3[0].Reduce();
		point_temp.Set(BSGS_MP3_double);
		point_temp = secp->Negation(point_temp);
		point_temp.Reduce();

		for(i = 1; i < 32; i++)	{
			BSGS_AMP3[i] = secp->AddDirect(BSGS_AMP3[i-1],point_temp);
			BSGS_AMP3[i].Reduce();
		}

		bytes = (uint64_t)bsgs_m3 * (uint64_t) sizeof(struct bsgs_xvalue);
		printf("[+] Allocating %.2f MB for %" PRIu64  " bP Points\n",(double)(bytes/1048576),bsgs_m3);
		
		bPtable = (struct bsgs_xvalue*) malloc(bytes);
		checkpointer((void *)bPtable,__FILE__,"malloc","bPtable" ,__LINE__ -1 );
		memset(bPtable,0,bytes);
		
		if(FLAGSAVEREADFILE)	{
			/*Reading file for 1st bloom filter */

			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_4_%" PRIu64 ".blm",bsgs_m);
			fd_aux1 = fopen(buffer_bloom_file,"rb");
			if(fd_aux1 != NULL)	{
				printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
				fflush(stdout);
				for(i = 0; i < 256;i++)	{
					bf_ptr = (char*) bloom_bP[i].bf;	/*We need to save the current bf pointer*/
					readed = fread(&bloom_bP[i],sizeof(struct bloom),1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					bloom_bP[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
					readed = fread(bloom_bP[i].bf,bloom_bP[i].bytes,1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					readed = fread(&bloom_bP_checksums[i],sizeof(struct checksumsha256),1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					if(FLAGSKIPCHECKSUM == 0)	{
						sha256((uint8_t*)bloom_bP[i].bf,bloom_bP[i].bytes,(uint8_t*)rawvalue);
						if(memcmp(bloom_bP_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bP_checksums[i].backup,rawvalue,32) != 0 )	{	/* Verification */
							fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
					}
					if(i % 64 == 0 )	{
						printf(".");
						fflush(stdout);
					}
				}
				printf(" Done!\n");
				fclose(fd_aux1);
				memset(buffer_bloom_file,0,1024);
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_3_%" PRIu64 ".blm",bsgs_m);
				fd_aux1 = fopen(buffer_bloom_file,"rb");
				if(fd_aux1 != NULL)	{
					printf("[W] Unused file detected %s you can delete it without worry\n",buffer_bloom_file);
					fclose(fd_aux1);
				}
				FLAGREADEDFILE1 = 1;
			}
			else	{	/*Checking for old file    keyhunt_bsgs_3_   */
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_3_%" PRIu64 ".blm",bsgs_m);
				fd_aux1 = fopen(buffer_bloom_file,"rb");
				if(fd_aux1 != NULL)	{
					printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						bf_ptr = (char*) bloom_bP[i].bf;	/*We need to save the current bf pointer*/
						readed = fread(&oldbloom_bP,sizeof(struct oldbloom),1,fd_aux1);
						
						/*
						if(FLAGDEBUG)	{
							printf("old Bloom filter %i\n",i);
							oldbloom_print(&oldbloom_bP);
						}
						*/
						
						if(readed != 1)	{
							fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						memcpy(&bloom_bP[i],&oldbloom_bP,sizeof(struct bloom));//We only need to copy the part data to the new bloom size, not from the old size
						bloom_bP[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
						
						readed = fread(bloom_bP[i].bf,bloom_bP[i].bytes,1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						memcpy(bloom_bP_checksums[i].data,oldbloom_bP.checksum,32);
						memcpy(bloom_bP_checksums[i].backup,oldbloom_bP.checksum_backup,32);
						memset(rawvalue,0,32);
						if(FLAGSKIPCHECKSUM == 0)	{
							sha256((uint8_t*)bloom_bP[i].bf,bloom_bP[i].bytes,(uint8_t*)rawvalue);
							if(memcmp(bloom_bP_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bP_checksums[i].backup,rawvalue,32) != 0 )	{	/* Verification */
								fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
								exit(EXIT_FAILURE);
							}
						}
						if(i % 32 == 0 )	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux1);
					FLAGUPDATEFILE1 = 1;	/* Flag to migrate the data to the new File keyhunt_bsgs_4_ */
					FLAGREADEDFILE1 = 1;
					
				}
				else	{
					FLAGREADEDFILE1 = 0;
					//Flag to make the new file
				}
			}
			
			/*Reading file for 2nd bloom filter */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_6_%" PRIu64 ".blm",bsgs_m2);
			fd_aux2 = fopen(buffer_bloom_file,"rb");
			if(fd_aux2 != NULL)	{
				printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
				fflush(stdout);
				for(i = 0; i < 256;i++)	{
					bf_ptr = (char*) bloom_bPx2nd[i].bf;	/*We need to save the current bf pointer*/
					readed = fread(&bloom_bPx2nd[i],sizeof(struct bloom),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					bloom_bPx2nd[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
					readed = fread(bloom_bPx2nd[i].bf,bloom_bPx2nd[i].bytes,1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					readed = fread(&bloom_bPx2nd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					memset(rawvalue,0,32);
					if(FLAGSKIPCHECKSUM == 0)	{								
						sha256((uint8_t*)bloom_bPx2nd[i].bf,bloom_bPx2nd[i].bytes,(uint8_t*)rawvalue);
						if(memcmp(bloom_bPx2nd_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bPx2nd_checksums[i].backup,rawvalue,32) != 0 )	{		/* Verification */
							fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
					}
					if(i % 64 == 0)	{
						printf(".");
						fflush(stdout);
					}
				}
				fclose(fd_aux2);
				printf(" Done!\n");
				memset(buffer_bloom_file,0,1024);
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_5_%" PRIu64 ".blm",bsgs_m2);
				fd_aux2 = fopen(buffer_bloom_file,"rb");
				if(fd_aux2 != NULL)	{
					printf("[W] Unused file detected %s you can delete it without worry\n",buffer_bloom_file);
					fclose(fd_aux2);
				}
				memset(buffer_bloom_file,0,1024);
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_1_%" PRIu64 ".blm",bsgs_m2);
				fd_aux2 = fopen(buffer_bloom_file,"rb");
				if(fd_aux2 != NULL)	{
					printf("[W] Unused file detected %s you can delete it without worry\n",buffer_bloom_file);
					fclose(fd_aux2);
				}
				FLAGREADEDFILE2 = 1;
			}
			else	{	
				FLAGREADEDFILE2 = 0;
			}
			
			/*Reading file for bPtable */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_2_%" PRIu64 ".tbl",bsgs_m3);
			fd_aux3 = fopen(buffer_bloom_file,"rb");
			if(fd_aux3 != NULL)	{
				printf("[+] Reading bP Table from file %s .",buffer_bloom_file);
				fflush(stdout);
				rsize = fread(bPtable,bytes,1,fd_aux3);
				if(rsize != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
				rsize = fread(checksum,32,1,fd_aux3);
				if(rsize != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
				if(FLAGSKIPCHECKSUM == 0)	{
					sha256((uint8_t*)bPtable,bytes,(uint8_t*)checksum_backup);
					if(memcmp(checksum,checksum_backup,32) != 0)	{
						fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
				}
				printf("... Done!\n");
				fclose(fd_aux3);
				FLAGREADEDFILE3 = 1;
			}
			else	{
				FLAGREADEDFILE3 = 0;
			}
			
			/*Reading file for 3rd bloom filter */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_7_%" PRIu64 ".blm",bsgs_m3);
			fd_aux2 = fopen(buffer_bloom_file,"rb");
			if(fd_aux2 != NULL)	{
				printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
				fflush(stdout);
				for(i = 0; i < 256;i++)	{
					bf_ptr = (char*) bloom_bPx3rd[i].bf;	/*We need to save the current bf pointer*/
					readed = fread(&bloom_bPx3rd[i],sizeof(struct bloom),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					bloom_bPx3rd[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
					readed = fread(bloom_bPx3rd[i].bf,bloom_bPx3rd[i].bytes,1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					readed = fread(&bloom_bPx3rd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					memset(rawvalue,0,32);
					if(FLAGSKIPCHECKSUM == 0)	{							
						sha256((uint8_t*)bloom_bPx3rd[i].bf,bloom_bPx3rd[i].bytes,(uint8_t*)rawvalue);
						if(memcmp(bloom_bPx3rd_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bPx3rd_checksums[i].backup,rawvalue,32) != 0 )	{		/* Verification */
							fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
					}
					if(i % 64 == 0)	{
						printf(".");
						fflush(stdout);
					}
				}
				fclose(fd_aux2);
				printf(" Done!\n");
				FLAGREADEDFILE4 = 1;
			}
			else	{
				FLAGREADEDFILE4 = 0;
			}
			
		}
		
		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE3 || !FLAGREADEDFILE4)	{
			if(FLAGREADEDFILE1 == 1)	{
				/* 
					We need just to make File 2 to File 4 this is
					- Second bloom filter 5%
					- third  bloom fitler 0.25 %
					- bp Table 0.25 %
				*/
				printf("[I] We need to recalculate some files, don't worry this is only 3%% of the previous work\n");
				FINISHED_THREADS_COUNTER = 0;
				FINISHED_THREADS_BP = 0;
				FINISHED_ITEMS = 0;
				salir = 0;
				BASE = 0;
				THREADCOUNTER = 0;
				if(THREADBPWORKLOAD >= bsgs_m2)	{
					THREADBPWORKLOAD = bsgs_m2;
				}
				THREADCYCLES = bsgs_m2 / THREADBPWORKLOAD;
				PERTHREAD_R = bsgs_m2 % THREADBPWORKLOAD;
				if(PERTHREAD_R != 0)	{
					THREADCYCLES++;
				}
				
				printf("\r[+] processing 1 %" PRIu64 "/%" PRIu64 " bP points : %i%%\r", FINISHED_ITEMS, bsgs_m, (int) (((double)FINISHED_ITEMS/(double)bsgs_m)*100));
				fflush(stdout);
				
				tid = new std::thread[NTHREADS];
				bPload_mutex = new std::mutex[NTHREADS];  // Array de mutexes para NTHREADS
				checkpointer((void *)bPload_mutex,__FILE__,"calloc","bPload_mutex" ,__LINE__ -1 );
				bPload_temp_ptr = (struct bPload*) calloc(NTHREADS,sizeof(struct bPload));
				checkpointer((void *)bPload_temp_ptr,__FILE__,"calloc","bPload_temp_ptr" ,__LINE__ -1 );
				bPload_threads_available = (char*) calloc(NTHREADS,sizeof(char));
				checkpointer((void *)bPload_threads_available,__FILE__,"calloc","bPload_threads_available" ,__LINE__ -1 );
				
				memset(bPload_threads_available,1,NTHREADS);
				
				for(j = 0; j < NTHREADS; j++)	{
					tid[i] = std::thread(thread_bPload, &bPload_temp_ptr[i]);
				}
				
				do	{
					for(j = 0; j < NTHREADS && !salir; j++)	{

						if(bPload_threads_available[j] && !salir)	{
							bPload_threads_available[j] = 0;
							bPload_temp_ptr[j].from = BASE;
							bPload_temp_ptr[j].threadid = j;
							bPload_temp_ptr[j].finished = 0;
							if( THREADCOUNTER < THREADCYCLES-1)	{
								bPload_temp_ptr[j].to = BASE + THREADBPWORKLOAD;
								bPload_temp_ptr[j].workload = THREADBPWORKLOAD;
							}
							else	{
								bPload_temp_ptr[j].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
								bPload_temp_ptr[j].workload = THREADBPWORKLOAD + PERTHREAD_R;
								salir = 1;
							}
							tid = new std::thread[NTHREADS];
							BASE+=THREADBPWORKLOAD;
							THREADCOUNTER++;
						}
					}

					if(OLDFINISHED_ITEMS != FINISHED_ITEMS)	{
						printf("\r[+] processing 2 %" PRIu64 "/%" PRIu64 " bP points : %i%%\r", FINISHED_ITEMS, bsgs_m2, (int) (((double)FINISHED_ITEMS / (double)bsgs_m2) * 100));
						fflush(stdout);
						OLDFINISHED_ITEMS = FINISHED_ITEMS;
					}
					
					for(j = 0 ; j < NTHREADS ; j++)	{
						finished = bPload_temp_ptr[j].finished;
						if(finished)	{
							bPload_temp_ptr[j].finished = 0;
							bPload_threads_available[j] = 1;
							FINISHED_ITEMS += bPload_temp_ptr[j].workload;
							FINISHED_THREADS_COUNTER++;
						}
					}
				}while(FINISHED_THREADS_COUNTER < THREADCYCLES);
				printf("\r[+] processing 3 %" PRIu64 "/%" PRIu64 " bP points : 100%%     \n", bsgs_m2, bsgs_m2);
				
				free(tid);
				free(bPload_mutex);
				free(bPload_temp_ptr);
				free(bPload_threads_available);
			}
			else{	
				/* We need just to do all the files 
					- first  bllom filter 100% 
					- Second bloom filter 5%
					- third  bloom fitler 0.25 %
					- bp Table 0.25 %
				*/
				FINISHED_THREADS_COUNTER = 0;
				FINISHED_THREADS_BP = 0;
				FINISHED_ITEMS = 0;
				salir = 0;
				BASE = 0;
				THREADCOUNTER = 0;
				if(THREADBPWORKLOAD >= bsgs_m)	{
					THREADBPWORKLOAD = bsgs_m;
				}
				THREADCYCLES = bsgs_m / THREADBPWORKLOAD;
				PERTHREAD_R = bsgs_m % THREADBPWORKLOAD;
				//if(FLAGDEBUG) printf("[D] THREADCYCLES: %lu\n",THREADCYCLES);
				if(PERTHREAD_R != 0)	{
					THREADCYCLES++;
					//if(FLAGDEBUG) printf("[D] PERTHREAD_R: %lu\n",PERTHREAD_R);
				}
				
				printf("\r[+] processing 4 %" PRIu64 "/%" PRIu64 " bP points : %i%%\r", FINISHED_ITEMS, bsgs_m, (int) (((double)FINISHED_ITEMS / (double)bsgs_m) * 100));
				fflush(stdout);
				tid = new std::thread[NTHREADS];
				bPload_mutex = new std::mutex[NTHREADS];
				checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
				checkpointer((void *)bPload_mutex,__FILE__,"calloc","bPload_mutex" ,__LINE__ -1 );
				
				bPload_temp_ptr = (struct bPload*) calloc(NTHREADS,sizeof(struct bPload));
				checkpointer((void *)bPload_temp_ptr,__FILE__,"calloc","bPload_temp_ptr" ,__LINE__ -1 );
				bPload_threads_available = (char*) calloc(NTHREADS,sizeof(char));
				checkpointer((void *)bPload_threads_available,__FILE__,"calloc","bPload_threads_available" ,__LINE__ -1 );
				

				memset(bPload_threads_available,1,NTHREADS);
				
				for(j = 0; j < NTHREADS; j++)	{
					tid[j] = std::thread(thread_bPload_2blooms, &bPload_temp_ptr[j]);
				}
				
				do {
					for(j = 0; j < NTHREADS && !salir; j++) {
						if(bPload_threads_available[j] && !salir) {
							bPload_threads_available[j] = 0;
							bPload_temp_ptr[j].from = BASE;
							bPload_temp_ptr[j].threadid = j;
							bPload_temp_ptr[j].finished = 0;
							
							if(THREADCOUNTER < THREADCYCLES - 1) {
								bPload_temp_ptr[j].to = BASE + THREADBPWORKLOAD;
								bPload_temp_ptr[j].workload = THREADBPWORKLOAD;
							} else {
								bPload_temp_ptr[j].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
								bPload_temp_ptr[j].workload = THREADBPWORKLOAD + PERTHREAD_R;
								salir = 1;
							}

							// Criação de threads corrigida
							try {
								// Criar a thread sem capturar uma exceção explicitamente
								tid[j] = std::thread(thread_bPload, &bPload_temp_ptr[j]);
							} catch (...) {
								std::cerr << "Failed to create thread " << j << std::endl;
								exit(EXIT_FAILURE);
							}


							BASE += THREADBPWORKLOAD;
							THREADCOUNTER++;
						}
					}

					// Atualização da saída
					if(OLDFINISHED_ITEMS != FINISHED_ITEMS) {
						printf("\r[+] processing 5 %" PRIu64 "/%" PRIu64 " bP points : %i%%\r", FINISHED_ITEMS, bsgs_m, (int) (((double)FINISHED_ITEMS / (double)bsgs_m) * 100));
						fflush(stdout);
						OLDFINISHED_ITEMS = FINISHED_ITEMS;
					}

					// Verificação dos estados das threads
					for(j = 0 ; j < NTHREADS ; j++) {
						finished = bPload_temp_ptr[j].finished;
						if(finished) {
    						bPload_temp_ptr[j].finished = 0;
							bPload_threads_available[j] = 1;
							FINISHED_ITEMS += bPload_temp_ptr[j].workload;
							FINISHED_THREADS_COUNTER++;
						}
					}
					fflush(stdout);
					
				} while(FINISHED_THREADS_COUNTER < THREADCYCLES);
				printf("\r[+] processing 6 %" PRIu64 "/%" PRIu64 " bP points : 100%%     \n", bsgs_m, bsgs_m);
				
				free(tid);
				free(bPload_mutex);
				free(bPload_temp_ptr);
				free(bPload_threads_available);
			}
		}

		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4) {
			printf("[+] Making checkums .. ");
			fflush(stdout);
		}	
		if(!FLAGREADEDFILE1) {
			for(i = 0; i < 256 ; i++)	{
				sha256((uint8_t*)bloom_bP[i].bf, bloom_bP[i].bytes,(uint8_t*) bloom_bP_checksums[i].data);
				memcpy(bloom_bP_checksums[i].backup,bloom_bP_checksums[i].data,32);
			}
			printf(".");
		}
		if(!FLAGREADEDFILE2) {
			for(i = 0; i < 256 ; i++)	{
				sha256((uint8_t*)bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes,(uint8_t*) bloom_bPx2nd_checksums[i].data);
				memcpy(bloom_bPx2nd_checksums[i].backup,bloom_bPx2nd_checksums[i].data,32);
			}
			printf(".");
		}
		if(!FLAGREADEDFILE4) {
			for(i = 0; i < 256 ; i++)	{
				sha256((uint8_t*)bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes,(uint8_t*) bloom_bPx3rd_checksums[i].data);
				memcpy(bloom_bPx3rd_checksums[i].backup,bloom_bPx3rd_checksums[i].data,32);
			}
			printf(".");
		}
		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4) {
			printf(" done\n");
			fflush(stdout);
		}	
		if(!FLAGREADEDFILE3) {
			printf("[+] Sorting %" PRIu64 " elements... ", bsgs_m3);
			fflush(stdout);
			bsgs_sort(bPtable,bsgs_m3);
			sha256((uint8_t*)bPtable, bytes,(uint8_t*) checksum);
			memcpy(checksum_backup,checksum,32);
			printf("Done!\n");
			fflush(stdout);
		}
		if(FLAGSAVEREADFILE || FLAGUPDATEFILE1 ) {
			if(!FLAGREADEDFILE1 || FLAGUPDATEFILE1)	{
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_4_%" PRIu64 ".blm",bsgs_m);
				
				if(FLAGUPDATEFILE1)	{
					printf("[W] Updating old file into a new one\n");
				}
				
				/* Writing file for 1st bloom filter */
				
				fd_aux1 = fopen(buffer_bloom_file,"wb");
				if(fd_aux1 != NULL)	{
					printf("[+] Writing bloom filter to file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						readed = fwrite(&bloom_bP[i],sizeof(struct bloom),1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(bloom_bP[i].bf,bloom_bP[i].bytes,1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(&bloom_bP_checksums[i],sizeof(struct checksumsha256),1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						if(i % 64 == 0)	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux1);
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
			}
			if(!FLAGREADEDFILE2  )	{
				
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_6_%" PRIu64 ".blm",bsgs_m2);
								
				/* Writing file for 2nd bloom filter */
				fd_aux2 = fopen(buffer_bloom_file,"wb");
				if(fd_aux2 != NULL)	{
					printf("[+] Writing bloom filter to file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						readed = fwrite(&bloom_bPx2nd[i],sizeof(struct bloom),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(bloom_bPx2nd[i].bf,bloom_bPx2nd[i].bytes,1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(&bloom_bPx2nd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						if(i % 64 == 0)	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux2);	
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
			}
			
			if(!FLAGREADEDFILE3)	{
				/* Writing file for bPtable */
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_2_%" PRIu64 ".tbl",bsgs_m3);
				fd_aux3 = fopen(buffer_bloom_file,"wb");
				if(fd_aux3 != NULL)	{
					printf("[+] Writing bP Table to file %s .. ",buffer_bloom_file);
					fflush(stdout);
					readed = fwrite(bPtable,bytes,1,fd_aux3);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					readed = fwrite(checksum,32,1,fd_aux3);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					printf("Done!\n");
					fclose(fd_aux3);	
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
			}
			if(!FLAGREADEDFILE4)	{
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_7_%" PRIu64 ".blm",bsgs_m3);
								
				/* Writing file for 3rd bloom filter */
				fd_aux2 = fopen(buffer_bloom_file,"wb");
				if(fd_aux2 != NULL)	{
					printf("[+] Writing bloom filter to file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						readed = fwrite(&bloom_bPx3rd[i],sizeof(struct bloom),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(bloom_bPx3rd[i].bf,bloom_bPx3rd[i].bytes,1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(&bloom_bPx3rd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						if(i % 64 == 0)	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux2);
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
			}
		}

		i = 0;

		steps = (uint64_t *) calloc(NTHREADS,sizeof(uint64_t));
		checkpointer((void *)steps,__FILE__,"calloc","steps" ,__LINE__ -1 );
		ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
		checkpointer((void *)ends,__FILE__,"calloc","ends" ,__LINE__ -1 );
		tid = new std::thread[NTHREADS];
		checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );

		for(j= 0;j < NTHREADS; j++)	{
			tt = (tothread*) malloc(sizeof(struct tothread));
			checkpointer((void *)tt,__FILE__,"malloc","tt" ,__LINE__ -1 );
			tt->nt = j;
			steps[j] = 0;
			s = 0;
			try {
				switch(FLAGBSGSMODE) {
					case 0:
						tid[j] = std::thread(thread_process_bsgs, (void *)tt);
						break;
				}
			} catch (const std::system_error &e) {
				std::cerr << "[E] Failed to create thread: " << e.what() << std::endl;
				exit(EXIT_FAILURE);
			}
		}
		free(aux);
		
	}
	
	for(j =0; j < 7; j++)	{
		int_limits[j].SetBase10((char*)str_limits[j]);
	}
	
	continue_flag = 1;
	total.SetInt32(0);
	pretotal.SetInt32(0);
	debugcount_mpz.Set(&BSGS_N);
	seconds.SetInt32(0);
	do	{
		sleep_ms(1000);
		seconds.AddOne();
		check_flag = 1;
		for(j = 0; j <NTHREADS && check_flag; j++) {
			check_flag &= ends[j];
		}
		if(check_flag)	{
			continue_flag = 0;
		}
		if(OUTPUTSECONDS.IsGreater(&ZERO) ){
			MPZAUX.Set(&seconds);
			MPZAUX.Mod(&OUTPUTSECONDS);
			if(MPZAUX.IsZero()) {
				total.SetInt32(0);
				for(j = 0; j < NTHREADS; j++) {
					pretotal.Set(&debugcount_mpz);
					pretotal.Mult(steps[j]);					
					total.Add(&pretotal);
				}
						
				pretotal.Set(&total);
				pretotal.Div(&seconds);
				str_seconds = seconds.GetBase10();
				str_pretotal = pretotal.GetBase10();
				str_total = total.GetBase10();
				
				
				if(pretotal.IsLower(&int_limits[0]))	{
					if(FLAGMATRIX)	{
						snprintf(buffer, sizeof(buffer), "[+] Total %s keys in %s seconds: %s keys/s\n", str_total, str_seconds, str_pretotal);
					}
					else	{
						snprintf(buffer, sizeof(buffer), "\r[+] Total %s keys in %s seconds: %s keys/s", str_total, str_seconds, str_pretotal);
					}
				}
				else	{
					i = 0;
					salir = 0;
					while( i < 6 && !salir)	{
						if(pretotal.IsLower(&int_limits[i+1]))	{
							salir = 1;
						}
						else	{
							i++;
						}
					}

					div_pretotal.Set(&pretotal);
					div_pretotal.Div(&int_limits[salir ? i : i-1]);
					str_divpretotal = div_pretotal.GetBase10();
					if (FLAGMATRIX) {
						snprintf(buffer, sizeof(buffer), "\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s )\r", str_total, str_seconds, str_divpretotal, str_limits_prefixs[salir ? i : i-1], str_pretotal);
					} else {
						if (THREADOUTPUT == 1) {
							// Mover o cursor uma linha acima
							printf("\033[A");  
							// Atualiza a linha total de chaves
							snprintf(buffer, sizeof(buffer), "\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)          ", 
									str_total, str_seconds, str_divpretotal, str_limits_prefixs[salir ? i : i-1], str_pretotal);
							fputs(buffer, stdout);
							fflush(stdout);
							// Voltar o cursor para a linha de baixo para o próximo update da thread
							printf("\033[B");
						} else {
							snprintf(buffer, sizeof(buffer), "\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s )\r", str_total, str_seconds, str_divpretotal, str_limits_prefixs[salir ? i : i-1], str_pretotal);
						}
					}
					free(str_divpretotal);

				}
				printf("%s",buffer);
				fflush(stdout);
				THREADOUTPUT = 0;
				free(str_seconds);
				free(str_pretotal);
				free(str_total);
			}
		}
	}while(continue_flag);
	printf("\nEnd\n");
}

/*	OK	*/
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b)	{
	struct bsgs_xvalue t;
	t	= *a;
	*a = *b;
	*b =	t;
}

/*	OK	*/
void bsgs_sort(struct bsgs_xvalue *arr,int64_t n)	{
	uint32_t depthLimit = ((uint32_t) ceil(log(n))) * 2;
	bsgs_introsort(arr,depthLimit,n);
}

/*	OK	*/
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n) {
	int64_t p;
	if(n > 1)	{
		if(n <= 16) {
			bsgs_insertionsort(arr,n);
		}
		else	{
			if(depthLimit == 0) {
				bsgs_myheapsort(arr,n);
			}
			else	{
				p = bsgs_partition(arr,n);
				if(p > 0) bsgs_introsort(arr , depthLimit-1 , p);
				if(p < n) bsgs_introsort(&arr[p+1],depthLimit-1,n-(p+1));
			}
		}
	}
}

/*	OK	*/
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n) {
	int64_t j;
	int64_t i;
	struct bsgs_xvalue key;
	for(i = 1; i < n ; i++ ) {
		key = arr[i];
		j= i-1;
		while(j >= 0 && memcmp(arr[j].value,key.value,BSGS_XVALUE_RAM) > 0) {
			arr[j+1] = arr[j];
			j--;
		}
		arr[j+1] = key;
	}
}

int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n)	{
	struct bsgs_xvalue pivot;
	int64_t r,left,right;
	r = n/2;
	pivot = arr[r];
	left = 0;
	right = n-1;
	do {
		while(left	< right && memcmp(arr[left].value,pivot.value,BSGS_XVALUE_RAM) <= 0 )	{
			left++;
		}
		while(right >= left && memcmp(arr[right].value,pivot.value,BSGS_XVALUE_RAM) > 0)	{
			right--;
		}
		if(left < right)	{
			if(left == r || right == r)	{
				if(left == r)	{
					r = right;
				}
				if(right == r)	{
					r = left;
				}
			}
			bsgs_swap(&arr[right],&arr[left]);
		}
	}while(left < right);
	if(right != r)	{
		bsgs_swap(&arr[right],&arr[r]);
	}
	return right;
}

void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i) {
	int64_t largest = i;
	int64_t l = 2 * i + 1;
	int64_t r = 2 * i + 2;
	if (l < n && memcmp(arr[l].value,arr[largest].value,BSGS_XVALUE_RAM) > 0)
		largest = l;
	if (r < n && memcmp(arr[r].value,arr[largest].value,BSGS_XVALUE_RAM) > 0)
		largest = r;
	if (largest != i) {
		bsgs_swap(&arr[i],&arr[largest]);
		bsgs_heapify(arr, n, largest);
	}
}

void bsgs_myheapsort(struct bsgs_xvalue	*arr, int64_t n)	{
	int64_t i;
	for ( i = (n / 2) - 1; i >=	0; i--)	{
		bsgs_heapify(arr, n, i);
	}
	for ( i = n - 1; i > 0; i--) {
		bsgs_swap(&arr[0] , &arr[i]);
		bsgs_heapify(arr, i, 0);
	}
}

int bsgs_searchbinary(struct bsgs_xvalue *buffer,char *data,int64_t array_length,uint64_t *r_value) {
	int64_t min,max,half,current;
	int r = 0,rcmp;
	min = 0;
	current = 0;
	max = array_length;
	half = array_length;
	while(!r && half >= 1) {
		half = (max - min)/2;
		rcmp = memcmp(data+16,buffer[current+half].value,BSGS_XVALUE_RAM);
		if(rcmp == 0)	{
			*r_value = buffer[current+half].index;
			r = 1;
		}
		else	{
			if(rcmp < 0) {
				max = (max-half);
			}
			else	{
				min = (min+half);
			}
			current = min;
		}
	}
	return r;
}

void* thread_process_bsgs(void* vargp) {
    // File-related variables
    FILE* filekey;
    struct tothread* tt;
	
	char* aux_c = nullptr;

    // Buffer fixo para auxiliar na otimização de impressão
    char print_buffer[128]; 

    // Character variables
    char xpoint_raw[32], *hextemp;

    // Integer variables
    Int base_key, keyfound;
    IntGroup* grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Int dy, dyn, _s, _p, km, intaux;

    // Point variables
    Point base_point, point_aux, point_found;
    Point startP;
    Point pp, pn;
    Point pts[CPU_GRP_SIZE];

    // Unsigned integer variables
    uint32_t k, l, r, salir, thread_number, cycles;

    // Other variables
    int hLength = (CPU_GRP_SIZE / 2 - 1);
    grp->Set(dx);

    tt = (struct tothread*)vargp;
    thread_number = tt->nt;
    free(tt);

    cycles = bsgs_aux / 1024;
    if (bsgs_aux % 1024 != 0) {
        cycles++;
    }
    intaux.Set(&BSGS_M_double);
    intaux.Mult(CPU_GRP_SIZE / 2);
    intaux.Add(&BSGS_M);

    do {
        base_key.Set(&BSGS_CURRENT);
        BSGS_CURRENT.Add(&BSGS_N_double);

        if (base_key.IsGreaterOrEqual(&n_range_end))
            break;

        if (FLAGMATRIX) {
            aux_c = base_key.GetBase16();
            snprintf(print_buffer, sizeof(print_buffer), "\n[+] Thread 0x%s \n", aux_c);
            fputs(print_buffer, stdout);
            fflush(stdout);
            free(aux_c);
        } else {
            if (FLAGQUIET == 0) {
				aux_c = base_key.GetBase16();
				// Usando \r para sobrescrever a linha, sem adicionar \n
				snprintf(print_buffer, sizeof(print_buffer), "\r[+] Thread 0x%s                                                                                   ", aux_c);
				fputs(print_buffer, stdout);
				fflush(stdout);
				free(aux_c);
				THREADOUTPUT = 1;
			}
        }

        base_point = secp->ComputePublicKey(&base_key);
        km.Set(&base_key);
        km.Neg();
        km.Add(&secp->order);
        km.Sub(&intaux);
        point_aux = secp->ComputePublicKey(&km);

        for (k = 0; k < bsgs_point_number; k++) {
			if (bsgs_found[k] == 0) {
				startP = secp->AddDirect(OriginalPointsBSGS[k], point_aux);
				uint32_t j = 0;

				while (j < cycles && bsgs_found[k] == 0) {
					int i;

					for (i = 0; i < hLength; i++) {
						dx[i].ModSub(&GSn[i].x, &startP.x);
					}
					dx[i].ModSub(&GSn[i].x, &startP.x);
					dx[i + 1].ModSub(&_2GSn.x, &startP.x);
					grp->ModInv();

					pts[CPU_GRP_SIZE / 2] = startP;
					for (i = 0; i < hLength; i++) {
						pp = startP;
						pn = startP;

						// P = startP + i*G
						dy.ModSub(&GSn[i].y, &pp.y);
						_s.ModMulK1(&dy, &dx[i]);
						_p.ModSquareK1(&_s);
						pp.x.ModNeg();
						pp.x.ModAdd(&_p);
						pp.x.ModSub(&GSn[i].x);

						// P = startP - i*G
						dyn.Set(&GSn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);
						_s.ModMulK1(&dyn, &dx[i]);
						_p.ModSquareK1(&_s);
						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&GSn[i].x);

						pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
						pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
					}

					// Última iteração para calcular o ponto negativo
					pn = startP;
					dyn.Set(&GSn[i].y);
					dyn.ModNeg();
					dyn.ModSub(&pn.y);
					_s.ModMulK1(&dyn, &dx[i]);
					_p.ModSquareK1(&_s);
					pn.x.ModNeg();
					pn.x.ModAdd(&_p);
					pn.x.ModSub(&GSn[i].x);
					pts[0] = pn;

					// Buffer para armazenar resultados de bloom
					std::vector<int> bloom_results(CPU_GRP_SIZE, 0);

					// Calcular todos os pontos primeiro
					for (int i = 0; i < CPU_GRP_SIZE; i++) {
						pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
						bloom_results[i] = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])], xpoint_raw, 32);
					}

					// Processar todos os resultados do bloom de uma vez
					for (int i = 0; i < CPU_GRP_SIZE && bsgs_found[k] == 0; i++) {
						
						if (bloom_results[i]) {
							// Executar a segunda verificação
							int second_check = bsgs_secondcheck(&base_key, ((j * 1024) + i), k, &keyfound);
							if (second_check) {
								hextemp = keyfound.GetBase16();
								char formatted_hextemp[65];
								int hextemp_len = strlen(hextemp);
								if (hextemp_len < 64) {
									memset(formatted_hextemp, '0', 64 - hextemp_len);
									strcpy(formatted_hextemp + (64 - hextemp_len), hextemp);
								} else {
									strcpy(formatted_hextemp, hextemp);
								}
								formatted_hextemp[64] = '\0';
								printf("\n[+] Thread Key found privkey %s   \n",formatted_hextemp);
								point_found = secp->ComputePublicKey(&keyfound);
								aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],point_found);
								printf("\n[+] Publickey %s\n",aux_c);
								filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
								if(filekey != NULL)	{
									fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
									fclose(filekey);
								}
								free(hextemp);
								free(aux_c);
								bsgs_found[k] = 1;
								salir = 1;
								for(l = 0; l < bsgs_point_number && salir; l++)	{
									salir &= bsgs_found[l];
								}
								if(salir)	{
									printf("All points were found\n");
									exit(EXIT_FAILURE);
								}
							}
						}
					}

					// Próxima iteração para atualizar o ponto
					pp = startP;
					dy.ModSub(&_2GSn.y, &pp.y);
					_s.ModMulK1(&dy, &dx[i + 1]);
					_p.ModSquareK1(&_s);
					pp.x.ModNeg();
					pp.x.ModAdd(&_p);
					pp.x.ModSub(&_2GSn.x);
					pp.y.ModSub(&_2GSn.x, &pp.x);
					pp.y.ModMulK1(&_s);
					pp.y.ModSub(&_2GSn.y);
					startP = pp;

					j++;
				}
			}
		}
        steps[thread_number] += 5;
    } while (1);

    // Gravar quaisquer dados restantes no buffer ao sair do loop
    if (buffer_index > 0) {
        filekey = fopen("KEYFOUNDKEYFOUND.txt", "a");
        if (filekey != NULL) {
            fwrite(key_buffer, 1, buffer_index, filekey);
            fclose(filekey);
        }
    }
    ends[thread_number] = 1;
    return NULL;
}

int bsgs_secondcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey)	{
	int i = 0,found = 0,r = 0;
	Int base_key;
	Point base_point,point_aux;
	Point BSGS_Q, BSGS_S,BSGS_Q_AMP;
	char xpoint_raw[32];


	base_key.Set(&BSGS_M_double);
	base_key.Mult((uint64_t) a);
	base_key.Add(start_range);

	base_point = secp->ComputePublicKey(&base_key);
	point_aux = secp->Negation(base_point);

	/*
		BSGS_S = Q - base_key
				 Q is the target Key
		base_key is the Start range + a*BSGS_M
	*/
	BSGS_S = secp->AddDirect(OriginalPointsBSGS[k_index],point_aux);
	BSGS_Q.Set(BSGS_S);
	do {
		BSGS_Q_AMP = secp->AddDirect(BSGS_Q,BSGS_AMP2[i]);
		BSGS_S.Set(BSGS_Q_AMP);
		BSGS_S.x.Get32Bytes((unsigned char *) xpoint_raw);
		r = bloom_check(&bloom_bPx2nd[(uint8_t) xpoint_raw[0]],xpoint_raw,32);
		if(r)	{
			found = bsgs_thirdcheck(&base_key,i,k_index,privatekey);
		}
		i++;
	}while(i < 128 && !found);
	return found;
}

int bsgs_thirdcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey)	{
	uint64_t j = 0;
	int i = 0,found = 0,r = 0;
	Int base_key,calculatedkey;
	Point base_point,point_aux;
	Point BSGS_Q, BSGS_S,BSGS_Q_AMP;
	char xpoint_raw[32];

	base_key.SetInt32(a);
	base_key.Mult(&BSGS_M2_double);
	base_key.Add(start_range);

	base_point = secp->ComputePublicKey(&base_key);
	point_aux = secp->Negation(base_point);
	
	BSGS_S = secp->AddDirect(OriginalPointsBSGS[k_index],point_aux);
	BSGS_Q.Set(BSGS_S);
	
	do {
		BSGS_Q_AMP = secp->AddDirect(BSGS_Q,BSGS_AMP3[i]);
		BSGS_S.Set(BSGS_Q_AMP);
		BSGS_S.x.Get32Bytes((unsigned char *)xpoint_raw);
		r = bloom_check(&bloom_bPx3rd[(uint8_t)xpoint_raw[0]],xpoint_raw,32);
		if(r)	{
			r = bsgs_searchbinary(bPtable,xpoint_raw,bsgs_m3,&j);
			if(r)	{
				calcualteindex(i,&calculatedkey);
				privatekey->Set(&calculatedkey);
				privatekey->Add((uint64_t)(j+1));
				privatekey->Add(&base_key);
				point_aux = secp->ComputePublicKey(privatekey);
				if(point_aux.x.IsEqual(&OriginalPointsBSGS[k_index].x))	{
					found = 1;
				}
				else	{
					calcualteindex(i,&calculatedkey);
					privatekey->Set(&calculatedkey);
					privatekey->Sub((uint64_t)(j+1));
					privatekey->Add(&base_key);
					point_aux = secp->ComputePublicKey(privatekey);
					if(point_aux.x.IsEqual(&OriginalPointsBSGS[k_index].x))	{
						found = 1;
					}
				}
			}
		}
		else	{
			/*
				For some reason the AddDirect don't return 000000... value when the publickeys are the negated values from each other
				Why JLP?
				This is is an special case
			*/
			if(BSGS_Q.x.IsEqual(&BSGS_AMP3[i].x))	{
				calcualteindex(i,&calculatedkey);
				privatekey->Set(&calculatedkey);
				privatekey->Add(&base_key);
				found = 1;
			}
		}
		i++;
	}while(i < 128 && !found);
	return found;
}

void sleep_ms(int milliseconds) {
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
}



void init_generator()	{
	Point G = secp->ComputePublicKey(&stride);
	Point g;
	g.Set(G);
	Gn.reserve(CPU_GRP_SIZE / 2);
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g,G);
		Gn[i] = g;
	}
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}

void *thread_bPload(void *vargp) {
    char rawvalue[32];
    struct bPload *tt;
    uint64_t i_counter, j, nbStep, to;

    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pts[CPU_GRP_SIZE];
    Int dy, dyn, _s, _p;
    Point pp, pn;

    int i, bloom_bP_index, hLength = (CPU_GRP_SIZE / 2 - 1), threadid;
    tt = (struct bPload *)vargp;
    Int km((uint64_t)(tt->from + 1));
    threadid = tt->threadid;

    // Initialize counters and steps
    i_counter = tt->from;
    nbStep = (tt->to - tt->from) / CPU_GRP_SIZE;

    // Check if there is a remainder step to handle
    if (((tt->to - tt->from) % CPU_GRP_SIZE) != 0) {
        nbStep++;
    }
    to = tt->to;

    // Prepare the starting point
    km.Add((uint64_t)(CPU_GRP_SIZE / 2));
    startP = secp->ComputePublicKey(&km);
    grp->Set(dx);

    // Processing loop
    for (uint64_t s = 0; s < nbStep && i_counter < to; s++) {
        // Calculate the differences (dx) for inversion
        for (i = 0; i < hLength; i++) {
            dx[i].ModSub(&Gn[i].x, &startP.x);
        }
        dx[i].ModSub(&Gn[i].x, &startP.x); // For the first point
        dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point
        grp->ModInv();

        // Initialize center point of the group
        pts[CPU_GRP_SIZE / 2] = startP;

        // Process positive and negative points from the center
        for (i = 0; i < hLength; i++) {
            pp = startP;
            pn = startP;

            // Calculate P + i*G
            dy.ModSub(&Gn[i].y, &pp.y);
            _s.ModMulK1(&dy, &dx[i]);
            _p.ModSquareK1(&_s);

            pp.x.ModNeg();
            pp.x.ModAdd(&_p);
            pp.x.ModSub(&Gn[i].x);

            // Calculate P - i*G
            dyn.Set(&Gn[i].y);
            dyn.ModNeg();
            dyn.ModSub(&pn.y);

            _s.ModMulK1(&dyn, &dx[i]);
            _p.ModSquareK1(&_s);

            pn.x.ModNeg();
            pn.x.ModAdd(&_p);
            pn.x.ModSub(&Gn[i].x);

            pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
            pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
        }

        // Iterate through the points and process bloom filters and tables
        for (j = 0; j < CPU_GRP_SIZE && i_counter < to; j++) {
            pts[j].x.Get32Bytes((unsigned char*)rawvalue);
            bloom_bP_index = (uint8_t)rawvalue[0];

            if (i_counter < bsgs_m3 && !FLAGREADEDFILE3) {
                memcpy(bPtable[i_counter].value, rawvalue + 16, BSGS_XVALUE_RAM);
                bPtable[i_counter].index = i_counter;
            }

            // Continue with the rest of the bloom filtering process...
            bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
            i_counter++;
        }

        // Update the start point for the next group
        pp = startP;
        dy.ModSub(&_2Gn.y, &pp.y);

        _s.ModMulK1(&dy, &dx[i + 1]);
        _p.ModSquareK1(&_s);

        pp.x.ModNeg();
        pp.x.ModAdd(&_p);
        pp.x.ModSub(&_2Gn.x);

        pp.y.ModSub(&_2Gn.x, &pp.x);
        pp.y.ModMulK1(&_s);
        pp.y.ModSub(&_2Gn.y);
        startP = pp;
    }
    tt->finished = 1;
    return NULL;
}

void *thread_bPload_2blooms(void *vargp) {
    char rawvalue[32];
    struct bPload *tt;
    uint64_t i_counter, j, nbStep;
    IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
    Point startP;
    Int dx[CPU_GRP_SIZE / 2 + 1];
    Point pts[CPU_GRP_SIZE];
    Int dy, dyn, _s, _p;
    Point pp, pn;
    int i, bloom_bP_index, hLength = (CPU_GRP_SIZE / 2 - 1), threadid;
    tt = (struct bPload *)vargp;
    Int km((uint64_t)(tt->from + 1));
    threadid = tt->threadid;

    i_counter = tt->from;
    nbStep = (tt->to - (tt->from)) / CPU_GRP_SIZE;

    if (((tt->to - (tt->from)) % CPU_GRP_SIZE) != 0) {
        nbStep++;
    }

    km.Add((uint64_t)(CPU_GRP_SIZE / 2));
    startP = secp->ComputePublicKey(&km);
    grp->Set(dx);

    for (uint64_t s = 0; s < nbStep; s++) {
        for (i = 0; i < hLength; i++) {
            dx[i].ModSub(&Gn[i].x, &startP.x);
        }
        dx[i].ModSub(&Gn[i].x, &startP.x); // For the first point
        dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point
        grp->ModInv();

        // We use the fact that P + i*G and P - i*G have the same deltax, so the same inverse
        // We compute key in the positive and negative way from the center of the group
        pts[CPU_GRP_SIZE / 2] = startP; // Center point

        for (i = 0; i < hLength; i++) {
            pp = startP;
            pn = startP;

            // P = startP + i*G
            dy.ModSub(&Gn[i].y, &pp.y);
            _s.ModMulK1(&dy, &dx[i]);
            _p.ModSquareK1(&_s);

            pp.x.ModNeg();
            pp.x.ModAdd(&_p);
            pp.x.ModSub(&Gn[i].x);

            // P = startP - i*G
            dyn.Set(&Gn[i].y);
            dyn.ModNeg();
            dyn.ModSub(&pn.y);
            _s.ModMulK1(&dyn, &dx[i]);
            _p.ModSquareK1(&_s);

            pn.x.ModNeg();
            pn.x.ModAdd(&_p);
            pn.x.ModSub(&Gn[i].x);

            pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
            pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
        }

        // First point (startP - (GRP_SIZE/2)*G)
        pn = startP;
        dyn.Set(&Gn[i].y);
        dyn.ModNeg();
        dyn.ModSub(&pn.y);

        _s.ModMulK1(&dyn, &dx[i]);
        _p.ModSquareK1(&_s);

        pn.x.ModNeg();
        pn.x.ModAdd(&_p);
        pn.x.ModSub(&Gn[i].x);

        pts[0] = pn;

        for (j = 0; j < CPU_GRP_SIZE; j++) {
            pts[j].x.Get32Bytes((unsigned char *)rawvalue);
            bloom_bP_index = (uint8_t)rawvalue[0];
            if (i_counter < bsgs_m3) {
                if (!FLAGREADEDFILE3) {
                    memcpy(bPtable[i_counter].value, rawvalue + 16, BSGS_XVALUE_RAM);
                    bPtable[i_counter].index = i_counter;
                }
                if (!FLAGREADEDFILE4) {
                    bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
                }
            }
            if (i_counter < bsgs_m2 && !FLAGREADEDFILE2) {
                bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
            }
            i_counter++;
        }

        // Next start point (startP + GRP_SIZE*G)
        pp = startP;
        dy.ModSub(&_2Gn.y, &pp.y);
        _s.ModMulK1(&dy, &dx[i + 1]);
        _p.ModSquareK1(&_s);

        pp.x.ModNeg();
        pp.x.ModAdd(&_p);
        pp.x.ModSub(&_2Gn.x);

        pp.y.ModSub(&_2Gn.x, &pp.x);
        pp.y.ModMulK1(&_s);
        pp.y.ModSub(&_2Gn.y);
        startP = pp;
    }

    delete grp;
    tt->finished = 1;
    return NULL;
}

void menu() {
	printf("\nUsage:\n");
	printf("-h          show this help\n");
	printf("-B Mode     BSGS now have some modes <sequential, backward, both, random, dance>\n");
	printf("-b bits     For some puzzles you only need some numbers of bits in the test keys.\n");
	printf("-c crypto   Search for specific crypto. <btc, eth> valid only w/ -m address\n");
	printf("-C mini     Set the minikey Base only 22 character minikeys, ex: SRPqx8QiwnW4WNWnTVa2W5\n");
	printf("-8 alpha    Set the bas58 alphabet for minikeys\n");
	printf("-e          Enable endomorphism search (Only for address, rmd160 and vanity)\n");
	printf("-f file     Specify file name with addresses or xpoints or uncompressed public keys\n");
	printf("-I stride   Stride for xpoint, rmd160 and address, this option don't work with bsgs\n");
	printf("-k value    Use this only with bsgs mode, k value is factor for M, more speed but more RAM use wisely\n");
	printf("-l look     What type of address/hash160 are you looking for <compress, uncompress, both> Only for rmd160 and address\n");
	printf("-m mode     mode of search for cryptos. (bsgs, xpoint, rmd160, address, vanity) default: address\n");
	printf("-M          Matrix screen, feel like a h4x0r, but performance will dropped\n");
	printf("-n number   Check for N sequential numbers before the random chosen, this only works with -R option\n");
	printf("            Use -n to set the N for the BSGS process. Bigger N more RAM needed\n");
	printf("-q          Quiet the thread output\n");
	printf("-r SR:EN    StarRange:EndRange, the end range can be omitted for search from start range to N-1 ECC value\n");
	printf("-R          Random, this is the default behavior\n");
	printf("-s ns       Number of seconds for the stats output, 0 to omit output.\n");
	printf("-S          S is for SAVING in files BSGS data (Bloom filters and bPtable)\n");
	printf("-6          to skip sha256 Checksum on data files");
	printf("-t tn       Threads number, must be a positive integer\n");
	printf("-v value    Search for vanity Address, only with -m vanity\n");
	printf("-z value    Bloom size multiplier, only address,rmd160,vanity, xpoint, value >= 1\n");
	printf("\nExample:\n\n");
	printf("./keyhunt -m rmd160 -f tests/unsolvedpuzzles.rmd -b 66 -l compress -R -q -t 8\n\n");
	printf("This line runs the program with 8 threads from the range 20000000000000000 to 40000000000000000 without stats output\n\n");
	printf("Developed by AlbertoBSD\tTips BTC: 1Coffee1jV4gB5gaXfHgSHDz9xx9QSECVW\n");
	printf("Thanks to Iceland always helping and sharing his ideas.\nTips to Iceland: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at\n\n");
	exit(EXIT_FAILURE);
}

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line)	{
	if(ptr == NULL)	{
		fprintf(stderr,"[E] error in file %s, %s pointer %s on line %i\n",file,function,name,line); 
		exit(EXIT_FAILURE);
	}
}

void calcualteindex(int i,Int *key)	{
	if(i == 0)	{
		key->Set(&BSGS_M3);
	}
	else	{
		key->SetInt32(i);
		key->Mult(&BSGS_M3_double);
		key->Add(&BSGS_M3);
	}
}
