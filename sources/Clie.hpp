
#include "client.hpp"
#include <memory>
#include <string>
#include <iostream>
#include <fstream>
#include <curl\curl.h>
#include <boost\filesystem.hpp>
#include <openssl\rsa.h>
#include <openssl\pem.h>
#include <openssl\applink.c>
#include <openssl\md5.h>
#include <iomanip>
#include <sstream>
#include <boost\asio\io_service.hpp>
#include <boost\bind.hpp>
#include <boost\thread\thread.hpp>
#include <map>
#include <openssl/evp.h>

#define BUFSIZE 1024
#define DISKDIRLEN 5
#define KEY_LENGHT 1024
#define BUFSIZEforHASH (1025*16)
#define CONF "conf.txt"
#define HISTORY "history.txt"
#define NEWHIST "newhist.txt"
#define PATHtoFILES "path.txt"
#define DIRF "dirf.txt"
namespace fs = boost::filesystem;

void Encrypt(std::string inn)
{
	std::string outn = inn + ".aes";
	int outlen, inlen;
	FILE *in = fopen(inn.c_str(), "rb"), 
		*out = fopen(outn.c_str(), "wb");
	unsigned char key[32] = "qwertytestqwertytestqwertytest"; // 256- битный ключ 
	unsigned char iv[8] = "1234567"; // вектор инициализации 
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER * cipher;
	EVP_CIPHER_CTX_init(&ctx);	// Обнуляем структуру контекста 
	cipher = EVP_aes_256_cfb();	// Выбираем алгоритм шифрования 
	EVP_EncryptInit(&ctx, cipher, key, iv);	// Инициализируем контекст алгоритма 
	for (;;) {	// Шифруем данные 
		inlen = fread(inbuf, 1, BUFSIZE, in);
		if (inlen <= 0) break;
		EVP_EncryptUpdate(&ctx, outbuf, &outlen, inbuf, inlen);
		fwrite(outbuf, 1, outlen, out);
	}
	EVP_EncryptFinal(&ctx, outbuf, &outlen);
	fwrite(outbuf, 1, outlen, out);
	EVP_CIPHER_CTX_cleanup(&ctx);
	fclose(in);
	fclose(out);
}

void Decrypt(std::string inn)
{
	std::string outn(inn);
	outn.erase(outn.end() - 4, outn.end());
	int outlen, inlen;
	FILE *in = fopen(inn.c_str(), "rb"),
		*out = fopen(outn.c_str(), "wb");
	unsigned char key[32] = "qwertytestqwertytestqwertytest"; // 256- битный ключ 
	unsigned char iv[8] = "1234567"; // вектор инициализации 
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER * cipher;
	EVP_CIPHER_CTX_init(&ctx);	// Обнуляем контекст и выбираем алгоритм дешифрования
	cipher = EVP_aes_256_cfb();	// Выбираем алгоритм шифрования 
	EVP_DecryptInit(&ctx, cipher, key, iv);
	for (;;) {// Дешифруем данные 
		inlen = fread(inbuf, 1, BUFSIZE, in);
		if (inlen <= 0) break;
		EVP_DecryptUpdate(&ctx, outbuf, &outlen, inbuf, inlen);
		fwrite(outbuf, 1, outlen, out);
	}
	EVP_DecryptFinal(&ctx, outbuf, &outlen);	// Завершаем процесс дешифрования 
	fwrite(outbuf, 1, outlen, out);
	EVP_CIPHER_CTX_cleanup(&ctx);
	fclose(in);
	fclose(out);
}

struct Info
{
	Info(const std::string filename) : filename_(filename)
	{
		std::ifstream file(filename_.c_str());
		if (!file.is_open()) throw("no_file");
		file >> login_ >> password_ >> dir_ >> url_;
	}
	std::string login_, password_, dir_, url_, filename_;
};

std::string GenHash(const char filename[]) // универсальная функция вычисления хэша
{
	EVP_MD_CTX mdctx; // Контекст для вычисления хэша
	const EVP_MD * md; // Структура с адресами функций алгоритма
	unsigned char buf[BUFSIZEforHASH];
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len; // Размер вычисленного хэша		
	int inf = _open(filename, O_RDWR);
	OpenSSL_add_all_digests();	// Добавляем алгоритмы хэширования во внутреннюю таблицу библиотеки
								// Получаем адреса функций алгоритма MD5 и инициализируем контекст для вычисления хэша
	md = EVP_get_digestbyname("md5"); // Универсальность)
	EVP_DigestInit(&mdctx, md);
	for (;;) {		// Вычисляем хэш 
		int i = _read(inf, buf, BUFSIZEforHASH);
		if (i <= 0) break;
		EVP_DigestUpdate(&mdctx, buf, (unsigned long)i);
	}
	EVP_DigestFinal(&mdctx, md_value, &md_len);	// Копируем вычисленный хэш в выходной буфер. Размер хэша сохраняем в переменной md_len
	EVP_MD_CTX_cleanup(&mdctx);	// Очищаем контекст
	_close(inf);
	//for (unsigned int  i = 0; i < md_len; i++) printf("%02x", md_value[i]);
	std::stringstream hash("");
	for (unsigned int i = 0; i < md_len; i++) hash << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << (md_value[i] & 0xFF);
	return hash.str();

	/*MD5_CTX c; // контекст хэша
	unsigned char buf[BUFSIZEforHASH];
	unsigned char md_buf[MD5_DIGEST_LENGTH];
	int f = _open("a1.txt", O_RDWR);
	MD5_Init(&c);	// Инициализируем контекст
	for (;;) {	// Вычисляем хэш
	int i = _read(f, buf, BUFSIZEforHASH);
	if (i <= 0) break;
	MD5_Update(&c, buf, (unsigned long)i);
	}
	MD5_Final(md_buf, &c);	// Помещаем вычисленный хэш в буфер md_buf
	// Отображаем результат
	for (auto i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", md_buf[i]);
	*/
}

void DirHP(const fs::path & dir)
{
	for (fs::directory_iterator it(dir), end; it != end; ++it)
	{
		if (fs::is_directory(*it)) {
			std::ofstream dirf(DIRF, std::ios::app);
			std::string dirn =  it->path().generic_string();
			dirf << std::endl << dirn;
			dirf.close();
			DirHP(*it);
			
		}
		else if (it->path().extension() != ".aes") {
			std::cout << "Обрабатывается файл - " << *it << std::endl;
			std::string fpath = it->path().generic_string();
			std::string hash = GenHash(fpath.c_str()); // получаем хэш
			std::cout << "Хэш - " << hash << std::endl;
			std::ifstream history(HISTORY);	// открываем файл с хэшами загруженныx файлов
			bool flag = TRUE;
			if (!history.is_open()) {}// throw("file's hash");
			else {
				std::string temphash;
				std::getline(history, temphash);
				while (!history.eof()) {
					std::getline(history, temphash);
					if (temphash == hash) {
						flag = FALSE;
						std::cout << "Файл уже загружался" << std::endl;
						break;
					}
				}
				history.close();
			}
			if (flag) {
				std::ofstream history(HISTORY, std::ios_base::app);
				std::ofstream ptf(PATHtoFILES, std::ios_base::app);
				history << std::endl << hash;
				ptf << std::endl << fpath;
				history.close();
				ptf.close();
			}
		}
	}
}

void DirP(const fs::path & dir)
{
	for (fs::directory_iterator it(dir), end; it != end; ++it)
	{
		if (fs::is_directory(*it)) {
			DirP(*it);
		}
		else if (it->path().extension() == ".aes") {
			std::cout << "Обрабатывается файл - " << *it << std::endl;
			std::string fpath = it->path().generic_string();
			std::ofstream ptf(PATHtoFILES, std::ios_base::app);
			ptf << std::endl << fpath;
			ptf.close();
		}
	}
}

void UtoD(std::string disk_dir = "/path")
{
	Info inf(CONF);
	DirHP(inf.dir_);
	std::ifstream ptf(PATHtoFILES);
	if (ptf.is_open()) {
		std::string path;
		std::getline(ptf, path);
		while (!ptf.eof()) {
			std::getline(ptf, path);
			Encrypt(path);
		}
		ptf.close();
	}
	std::map<std::string, std::string> options =
	{
		{ "webdav_hostname", inf.url_.c_str() },
		{ "webdav_login",    inf.login_.c_str() },
		{ "webdav_password", inf.password_.c_str() }
	};
	std::unique_ptr<WebDAV::Client> client(WebDAV::Client::Init(options));
	//client->create_directory(disk_dir);
	std::ifstream dirf(DIRF);
	if (dirf.is_open()) {
		std::string temp;
		std::getline(dirf, temp);
		while (!dirf.eof()) {
			std::getline(dirf, temp);
			temp.erase(0, inf.dir_.end() - inf.dir_.begin() + 1);
			client->create_directory(disk_dir + "/" + temp);
		}
		dirf.close();
		std::remove(DIRF);
	}
	std::ifstream pathf(PATHtoFILES);
	if (pathf.is_open()) {
		std::string temp, tempd;
		std::getline(pathf, temp);
		while (!pathf.eof()) {
			std::getline(pathf, temp);
			temp = temp + ".aes";
			std::string tempd(temp);
			tempd.erase(0, inf.dir_.end() - inf.dir_.begin() + 1);
			client->upload(disk_dir + "/" + tempd, temp);
			std::remove(temp.c_str());
		}
		pathf.close();
		std::remove(PATHtoFILES);
	}
}



/*void decrypt_threads(std::string dir_name)
{
boost::asio::io_service ioService;
boost::thread_group threadpool;
boost::asio::io_service::work work(ioService);
for (size_t i = 0; i < 2; i++) {
threadpool.create_thread(boost::bind(&boost::asio::io_service::run, &ioService));
}
for (boost::filesystem::recursive_directory_iterator it(dir_name), end; it != end; ++it) {
auto current_file = it->path();
if (!is_directory(current_file))
{
if (current_file.extension() == ".crpt") {
auto new_name(current_file.string().substr(0, current_file.string().find(".crpt")));
ioService.post(boost::bind(decryptfile, new_name));
}
}
}
ioService.stop();
threadpool.join_all();
}*/


void RD(std::unique_ptr<WebDAV::Client> & client, std::string dir, std::string disk_dir)
{
	std::string ds(disk_dir);
	ds.erase(ds.begin(), ds.begin() + DISKDIRLEN); //warn
	boost::filesystem::create_directory(dir + "/" + ds);
	auto files = client->list(disk_dir);
	for (auto i : files) {
		if (client->is_dir(disk_dir + i)) {

			RD(client, dir, disk_dir + i);
		}
		else {
			std::string tmp(i);
			std::string aes = ".aes";
			tmp.erase(tmp.begin(), tmp.end() - 4);
			if (tmp == aes) {
				client->download(disk_dir + i, dir + "/" + ds + "/" + i);
			}
		}
	}
}

void DfromD()
{
	Info inf(CONF);
	std::map<std::string, std::string> options =
	{
		{ "webdav_hostname", inf.url_.c_str() },
		{ "webdav_login",    inf.login_.c_str() },
		{ "webdav_password", inf.password_.c_str() }
	};
	std::unique_ptr<WebDAV::Client> client(WebDAV::Client::Init(options));
	RD(client, inf.dir_, "path/");

	DirP(inf.dir_);
	std::vector<std::string> nh;
	std::ifstream ptf(PATHtoFILES);
	boost::asio::io_service ioService;
	boost::thread_group threadpool;
	boost::asio::io_service::work work(ioService);
	for (size_t i = 0; i < 2; i++) {
		threadpool.create_thread(boost::bind(&boost::asio::io_service::run, &ioService));
	}
	if (ptf.is_open()) {
		std::string path;
		std::getline(ptf, path);
		while (!ptf.eof()) {
			std::getline(ptf, path);
			ioService.post(boost::bind(&Decrypt, path));
			Decrypt(path);
			std::remove(path.c_str());
			std::string fpath(path);
			fpath.erase(fpath.end() - 4, fpath.end());
			std::string hash = GenHash(fpath.c_str()); // Получаем хэш
			nh.push_back(hash);
		}
		ioService.stop();
		threadpool.join_all();
		ptf.close();
		std::remove(PATHtoFILES);
	}
	std::ifstream hist(HISTORY);
	std::vector<std::string> oh;
	std::string tmp;
	std::getline(hist, tmp);
	while (!hist.eof()) {
		std::getline(hist, tmp);
		oh.push_back(tmp);
	}
	hist.close();
	std::remove(HISTORY);
	std::ofstream nhist(HISTORY);
	bool flag;
	for (auto i : oh) {
		flag = TRUE;
		for (auto j : nh) {
			if (i == j) {
				flag = FALSE;
				break;
			}
		}
		if (flag) nhist << std::endl << i;
	}
	nhist.close();
}

int main() {
	setlocale(LC_ALL, "Russian");
	int n;
	std::cout << "1 - Отправка на Яндекс Диск" << std::endl << "2 - Загрузка с Яндекс Диска" << std::endl;
	std::cin >> n;
	if (n==1) UtoD();
	else if (n==2) DfromD();
	system("pause");
	return 0;
}

/*
#define PRIVAT "privat.key"
#define PUBLIC "public.key"
#define SECRET_WORD "secret"
void GenKeys(char secret[]) {
RSA * rsa = NULL;	// указатель на структуру для хранения ключей
unsigned long bits = KEY_LENGHT;
FILE * privKey_file = NULL, *pubKey_file = NULL;
const EVP_CIPHER *cipher = NULL;	// контекст алгоритма шифрования
privKey_file = fopen(PRIVAT, "wb");
pubKey_file = fopen(PUBLIC, "wb");
rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
cipher = EVP_get_cipherbyname("bf-ofb");	// Формируем контекст алгоритма шифрования
PEM_write_RSAPrivateKey(privKey_file, rsa, cipher, NULL, 0, NULL, secret);
PEM_write_RSAPublicKey(pubKey_file, rsa);
RSA_free(rsa);
fclose(privKey_file);
fclose(pubKey_file);
std::cout << "Ключи сгенерированы" << std::endl;
}

void Encrypt(std::string inname) {

// Cтруктура для хранения открытого ключа
RSA * pubKey = NULL;
FILE * pubKey_file = NULL;
unsigned char *ctext, *ptext;
int inlen, outlen;
// Считываем открытый ключ
pubKey_file = fopen(PUBLIC, "rb");
pubKey = PEM_read_RSAPublicKey(pubKey_file, NULL, NULL, NULL);
fclose(pubKey_file);
int key_size = RSA_size(pubKey);	// Определяем длину ключа
ctext = (unsigned char *)malloc(key_size);
ptext = (unsigned char *)malloc(key_size);
OpenSSL_add_all_algorithms();
std::string outname = inname + ".rsa";
int out = _open(outname.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0600);
int in = _open(inname.c_str(), O_RDWR);
while (TRUE) {		// Шифруем содержимое входного файла
inlen = _read(in, ptext, key_size - 11);
if (inlen <= 0) break;
outlen = RSA_public_encrypt(inlen, ptext, ctext, pubKey, RSA_PKCS1_PADDING);
if (outlen != RSA_size(pubKey)) exit(-1);
_write(out, ctext, outlen);
}
free(ctext);
free(ptext);
RSA_free(pubKey);
_close(out);
_close(in);
std::cout << "Содержимое файла " << inname << " было зашифровано" << std::endl;
}

void Decrypt(std::string inname, char secret[] = SECRET_WORD) {
RSA * privKey = NULL;
FILE * privKey_file;
unsigned char *ptext, *ctext;
int inlen, outlen;
OpenSSL_add_all_algorithms();
privKey_file = fopen(PRIVAT, "rb");
privKey = PEM_read_RSAPrivateKey(privKey_file, NULL, NULL, secret);
int key_size = RSA_size(privKey); // Определяем длину ключа
ptext = (unsigned char *)malloc(key_size);
ctext = (unsigned char *)malloc(key_size);
std::string outname(inname);
outname.erase(outname.end() - 4, outname.end());
int out = _open(outname.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0600);
int in = _open(inname.c_str(), O_RDWR);
while (1) {	// Дешифруем файл
inlen = _read(in, ctext, key_size);
if (inlen <= 0) break;
outlen = RSA_private_decrypt(inlen, ctext, ptext, privKey, RSA_PKCS1_PADDING);
if (outlen < 0) exit(0);
_write(out, ptext, outlen);
}
free(ctext);
free(ptext);
RSA_free(privKey);
_close(in);
_close(out);
std::cout << "Содержимое файла " << inname << " было дешифровано" << std::endl;

}
*/