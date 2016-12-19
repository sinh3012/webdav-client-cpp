#include <webdav/client.hpp>
#include <memory>
#include <string>
#include <iostream>
#include <fstream>
#include <curl/curl.h>
#include <boost/filesystem.hpp>
#include <openssl/rsa.h>
#include <openssl/pem.h>
//#include <openssl/applink.c>
#include <openssl/md5.h>
#include <iomanip>
#include <sstream>
#include <boost/asio/io_service.hpp>
#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>
#include <boost/asio.hpp>
#include <boost/bind/rotect.hpp>

#include <map>
#include <openssl/evp.h>

#define BUFSIZE 1024
#define IV "1234567"
#define KEY "qwertytestqwertytestqwertytest"
#define BUFSIZEforHASH (1025*16)
#define CONF "conf.txt"
#define HISTORY "history.txt"
#define PATHtoFILES "path.txt"
#define DIRF "dirf.txt"
#define DISKDIRLEN 5

namespace fs = boost::filesystem;

void Encrypt(std::string inn) // Шифрование AES
{
	std::string outn = inn + ".aes";
	int outlen, inlen;
	FILE *in = fopen(inn.c_str(), "rb"), 
		*out = fopen(outn.c_str(), "wb");
	unsigned char key[32] = KEY; // 256 - битный ключ 
	unsigned char iv[8] = IV; // Dектор инициализации 
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

void Decrypt(std::string inn) // Расшифровка AES
{
	std::string outn(inn);
	outn.erase(outn.end() - 4, outn.end());
	int outlen, inlen;
	FILE *in = fopen(inn.c_str(), "rb"),
		*out = fopen(outn.c_str(), "wb");
	unsigned char key[32] = KEY; // 256- битный ключ 
	unsigned char iv[8] = IV; // вектор инициализации 
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER * cipher;
	EVP_CIPHER_CTX_init(&ctx);	// Обнуляем контекст и выбираем алгоритм дешифрования
	cipher = EVP_aes_256_cfb();	// Выбираем алгоритм шифрования 
	EVP_DecryptInit(&ctx, cipher, key, iv);
	for (;;) {	// Дешифруем данные 
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

std::string GenHash(const char filename[]) // Универсальная функция вычисления хэша
{
	EVP_MD_CTX mdctx; // Контекст для вычисления хэша
	const EVP_MD * md; // Структура с адресами функций алгоритма
	unsigned char buf[BUFSIZEforHASH];
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len; // Размер вычисленного хэша		
	FILE *inf = fopen(filename, "rb");
	OpenSSL_add_all_digests();	// Добавляем алгоритмы хэширования во внутреннюю таблицу библиотеки
								// Получаем адреса функций алгоритма MD5 и инициализируем контекст для вычисления хэша
	md = EVP_get_digestbyname("md5"); // Универсальность)
	EVP_DigestInit(&mdctx, md);
	for (;;) {		// Вычисляем хэш 
		int i = fread(buf, 1, BUFSIZEforHASH, inf);
		if (i <= 0) break;
		EVP_DigestUpdate(&mdctx, buf, (unsigned long)i);
	}
	EVP_DigestFinal(&mdctx, md_value, &md_len);	// Копируем вычисленный хэш в выходной буфер. Размер хэша сохраняем в переменной md_len
	EVP_MD_CTX_cleanup(&mdctx);	// Очищаем контекст
	fclose(inf);
	//for (unsigned int  i = 0; i < md_len; i++) printf("%02x", md_value[i]);
	std::stringstream hash("");
	for (unsigned int i = 0; i < md_len; i++) hash << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << (md_value[i] & 0xFF);
	return hash.str();
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
			if (!history.is_open()) {}
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

void UtoD(std::string disk_dir = "/path") // Загрузить в диск
{
	Info inf(CONF);
	DirHP(inf.dir_);
	bool flag = 0;
	std::ifstream ptf(PATHtoFILES);
	if (ptf.is_open()) {
		flag = 1;
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
	if (dirf.is_open() && flag) {
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

void RD(std::unique_ptr<WebDAV::Client> & client, std::string dir, std::string disk_dir)
{
	std::string ds(disk_dir);
	ds.erase(ds.begin(), ds.begin() + DISKDIRLEN);
	boost::filesystem::create_directory(dir + "/" + ds);
	auto files = client->list(disk_dir);
	for (auto i : files) {
		if (client->is_dir(disk_dir + i)) {
			RD(client, dir, disk_dir + i);
			client->clean(disk_dir + i);
		}
		else {
			std::string tmp(i);
			std::string aes = ".aes";
			tmp.erase(tmp.begin(), tmp.end() - 4);
			if (tmp == aes) {
				client->download(disk_dir + i, dir + "/" + ds + "/" + i);
				client->clean(disk_dir + i);
			}
		}
	}
}

void DfromD(std::string filename = CONF) //Загрузка из диска
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
	std::vector<std::string> paths;
	std::ifstream ptf(PATHtoFILES);
	if (ptf.is_open()) {
		std::string path;
		std::getline(ptf, path);
		while (!ptf.eof()) {
			std::getline(ptf, path);
			paths.push_back(path);
		}
		ptf.close();
		std::remove(PATHtoFILES);
	}
	// Потоки ... заработали)
	boost::asio::io_service ioService;
	boost::thread_group threadpool;
	boost::asio::io_service::work work(ioService);
	for (size_t i = 0; i < 2; i++) {
		threadpool.create_thread(boost::bind(&boost::asio::io_service::run, &ioService));
	}
	for (auto i : paths) {
		ioService.post(boost::bind(&Decrypt, i));
	}
	ioService.stop();
	threadpool.join_all();
	for (auto i : paths) {
		std::remove(i.c_str());
	}
	
}

int main() {
	setlocale(LC_ALL, "Russian");
	int n;
	std::cout << "1 - Отправка на Яндекс Диск" << std::endl << "2 - Загрузка с Яндекс Диска" << std::endl
		<< "3 - Загрузить файлы с нескольких аккаунтов" << std::endl;
	std::cin >> n;
	if (n==1) UtoD();
	else if (n==2) DfromD();
	else if (n == 3) {
		std::cout << "Введите количество аккаунтов" << std::endl;
		std::cin >> n;
		DfromManyD(n);
	}
	system("pause");
	return 0;
}
