
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
	unsigned char key[32] = "qwertytestqwertytestqwertytest"; // 256- áèòíûé êëþ÷ 
	unsigned char iv[8] = "1234567"; // âåêòîð èíèöèàëèçàöèè 
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER * cipher;
	EVP_CIPHER_CTX_init(&ctx);	// Îáíóëÿåì ñòðóêòóðó êîíòåêñòà 
	cipher = EVP_aes_256_cfb();	// Âûáèðàåì àëãîðèòì øèôðîâàíèÿ 
	EVP_EncryptInit(&ctx, cipher, key, iv);	// Èíèöèàëèçèðóåì êîíòåêñò àëãîðèòìà 
	for (;;) {	// Øèôðóåì äàííûå 
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
	unsigned char key[32] = "qwertytestqwertytestqwertytest"; // 256- áèòíûé êëþ÷ 
	unsigned char iv[8] = "1234567"; // âåêòîð èíèöèàëèçàöèè 
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE];
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER * cipher;
	EVP_CIPHER_CTX_init(&ctx);	// Îáíóëÿåì êîíòåêñò è âûáèðàåì àëãîðèòì äåøèôðîâàíèÿ
	cipher = EVP_aes_256_cfb();	// Âûáèðàåì àëãîðèòì øèôðîâàíèÿ 
	EVP_DecryptInit(&ctx, cipher, key, iv);
	for (;;) {// Äåøèôðóåì äàííûå 
		inlen = fread(inbuf, 1, BUFSIZE, in);
		if (inlen <= 0) break;
		EVP_DecryptUpdate(&ctx, outbuf, &outlen, inbuf, inlen);
		fwrite(outbuf, 1, outlen, out);
	}
	EVP_DecryptFinal(&ctx, outbuf, &outlen);	// Çàâåðøàåì ïðîöåññ äåøèôðîâàíèÿ 
	fwrite(outbuf, 1, outlen, out);
	EVP_CIPHER_CTX_cleanup(&ctx);
	fclose(in);
	fclose(out);
	std::cout << "DECRIPT" << std::endl
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

std::string GenHash(const char filename[]) // óíèâåðñàëüíàÿ ôóíêöèÿ âû÷èñëåíèÿ õýøà
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
			std::cout << "Îáðàáàòûâàåòñÿ ôàéë - " << *it << std::endl;
			std::string fpath = it->path().generic_string();
			std::string hash = GenHash(fpath.c_str()); // ïîëó÷àåì õýø
			std::cout << "Õýø - " << hash << std::endl;
			std::ifstream history(HISTORY);	// îòêðûâàåì ôàéë ñ õýøàìè çàãðóæåííûx ôàéëîâ
			bool flag = 1;
			if (!history.is_open()) {}// throw("file's hash");
			else {
				std::string temphash;
				std::getline(history, temphash);
				while (!history.eof()) {
					std::getline(history, temphash);
					if (temphash == hash) {
						flag = 0;
						std::cout << "Ôàéë óæå çàãðóæàëñÿ" << std::endl;
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
			std::cout << "Îáðàáàòûâàåòñÿ ôàéë - " << *it << std::endl;
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

void RD(std::unique_ptr<WebDAV::Client> & client, std::string dir, std::string disk_dir)
{
	std::string ds(disk_dir);
	ds.erase(ds.begin(), ds.begin() + DISKDIRLEN); //warn
	boost::filesystem::create_directory(dir + "/" + ds);
	auto files = client->list(disk_dir);
	std::cout << disk_dir << std::endl;
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
	std::cout << "DirP" << std::endl;
	std::vector<std::string> nh;
	std::ifstream ptf(PATHtoFILES);
	/*boost::asio::io_service ioService;
	boost::thread_group threadpool;
	boost::asio::io_service::work work(ioService);
	for (size_t i = 0; i < 2; i++) {
		threadpool.create_thread(boost::bind(&boost::asio::io_service::run, &ioService));
	}*/
	if (ptf.is_open()) {
		std::string path;
		std::getline(ptf, path);
		while (!ptf.eof()) {
			std::getline(ptf, path);
			//ioService.post(boost::bind(&Decrypt, path));
			Decrypt(path);
			std::remove(path.c_str());
			std::string fpath(path);
			fpath.erase(fpath.end() - 4, fpath.end());
			std::string hash = GenHash(fpath.c_str()); // Ïîëó÷àåì õýø
			nh.push_back(hash);
		}
		//ioService.stop();
		//threadpool.join_all();
		ptf.close();
		std::remove(PATHtoFILES);
	}
	std::cout << "DECRIPTALL" << std::endl;
	std::ifstream hist(HISTORY);
	std::vector<std::string> oh;
	std::string tmp;
	std::getline(hist, tmp);
	while (!hist.eof()) {
		std::getline(hist, tmp);
		oh.push_back(tmp);
	}
	hist.close();
	std::cout << "HistDESTR" << std::endl;
	std::remove(HISTORY);
	std::ofstream nhist(HISTORY);
	bool flag;
	for (auto i : oh) {
		flag = 1;
		for (auto j : nh) {
			if (i == j) {
				flag = 0;
				break;
			}
		}
		if (flag) nhist << std::endl << i;
	}
	nhist.close();
}
/*
int main() {
	setlocale(LC_ALL, "Russian");
	int n;
	std::cout << "1 - Îòïðàâêà íà ßíäåêñ Äèñê" << std::endl << "2 - Çàãðóçêà ñ ßíäåêñ Äèñêà" << std::endl;
	std::cin >> n;
	if (n==1) UtoD();
	else if (n==2) DfromD();
	system("pause");
	return 0;
}*/
