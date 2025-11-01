#include <iostream>

#include <AtomicDeque.hpp>
#include <BufferWriter.hpp>
#include <CertStore.hpp>
#include <HttpRequest.hpp>
#include <hwHid.hpp>
#include <main.hpp>
#include <rsa.hpp>
#include <Server.hpp>
#include <ServerWebService.hpp>
#include <Socket.hpp>
#include <string.hpp>
#include <Thread.hpp>
#include <WebSocketMessage.hpp>

#define DEBUG false

using namespace soup;

// Based on https://source.chromium.org/chromium/chromium/src/+/main:services/device/public/cpp/hid/hid_blocklist.cc
[[nodiscard]] static bool hid_is_permitted(const hwHid& hid)
{
	return hid.usage_page != 0xF1D0 // FIDO page
		&& hid.vendor_id != 0x096E // Feitian Technologies (incl. KEY-ID & HyperFIDO)
		&& hid.vendor_id != 0x1050 // Yubico
		&& !(hid.vendor_id == 0x09C3 && hid.product_id == 0x0023) // HID Global BlueTrust Token
		&& !(hid.vendor_id == 0x10C4 && hid.product_id == 0x8ACF) // U2F Zero
		&& !(hid.vendor_id == 0x1209 && hid.product_id == 0x4321) // Mooltipass Mini-BLE
		&& !(hid.vendor_id == 0x1209 && hid.product_id == 0x4322) // Mooltipass Arduino sketch
		&& !(hid.vendor_id == 0x18D1 && hid.product_id == 0x5026) // Titan
		&& !(hid.vendor_id == 0x1A44 && hid.product_id == 0x00BB) // VASCO
		&& !(hid.vendor_id == 0x1D50 && hid.product_id == 0x60FC) // OnlyKey
		&& !(hid.vendor_id == 0x1E0D && hid.product_id == 0xF1AE) // Keydo AES
		&& !(hid.vendor_id == 0x1E0D && hid.product_id == 0xF1D0) // Neowave Keydo
		&& !(hid.vendor_id == 0x1EA8 && hid.product_id == 0xF025) // Thetis
		&& !(hid.vendor_id == 0x20A0 && hid.product_id == 0x4287) // Nitrokey
		&& !(hid.vendor_id == 0x24DC && hid.product_id == 0x0101) // JaCarta
		&& !(hid.vendor_id == 0x2581 && hid.product_id == 0xF1D0) // Happlink
		&& !(hid.vendor_id == 0x2ABE && hid.product_id == 0x1002) // Bluink
		&& !(hid.vendor_id == 0x2CCF && hid.product_id == 0x0880) // Feitian USB, HyperFIDO
		;
}

[[nodiscard]] static uint32_t hid_to_physical_hash(const hwHid& hid)
{
	uint32_t hash = soup::joaat::INITIAL;
	hash = soup::joaat::hashRange((const char*)&hid.vendor_id, sizeof(hid.vendor_id), hash);
	hash = soup::joaat::hashRange((const char*)&hid.product_id, sizeof(hid.product_id), hash);
	hash = soup::joaat::hash(hid.getManufacturerName(), hash);
	hash = soup::joaat::hash(hid.getProductName(), hash);
	hash = soup::joaat::hash(hid.getSerialNumber(), hash);
	return hash;
}

[[nodiscard]] static uint32_t hid_to_hash(const hwHid& hid)
{
	return soup::joaat::hash(hid.path);
}

struct ReceiveReportsTask;

struct ClientData
{
	std::vector<ReceiveReportsTask*> subscriptions;
	bool supports_report_ids = false;

	[[nodiscard]] ReceiveReportsTask* findSubscription(uint32_t hid_hash) const noexcept;
};

struct ReceiveReportsTask : public soup::Task
{
	SharedPtr<Worker> sock;
	hwHid hid;
	uint32_t hid_hash;
	Thread thrd;
	AtomicDeque<std::string> deque;
	bool report_ids;

	ReceiveReportsTask(SharedPtr<Worker>&& _sock, hwHid&& hid, uint32_t hid_hash)
		: sock(std::move(_sock)), hid(std::move(hid)), hid_hash(hid_hash), thrd(&thrd_run, this), report_ids(static_cast<Socket&>(*sock).custom_data.getStructFromMap(ClientData).supports_report_ids)
	{
		static_cast<Socket&>(*sock).custom_data.getStructFromMap(ClientData).subscriptions.emplace_back(this);
	}

	static void thrd_run(Capture&& cap)
	{
		ReceiveReportsTask& task = cap.get<ReceiveReportsTask>();
		while (true)
		{
			const Buffer<>& report = (task.report_ids ? task.hid.receiveReportWithReportId() : task.hid.receiveReportWithoutReportId());
			SOUP_IF_UNLIKELY (report.empty())
			{
				//std::cout << "received empty report for " << task.hid_hash << std::endl;
				break;
			}
			//std::cout << "received report for " << task.hid_hash << std::endl;
			BufferWriter bw;
			uint8_t msgid = (task.report_ids ? 1 : 0); bw.u8(msgid);
			bw.u32_be(task.hid_hash);
			bw.buf.append(report);
			task.deque.emplace_front(bw.buf.toString());
		}
		//std::cout << "thread stopping for " << task.hid_hash << std::endl;
	}

	void unsubscribe()
	{
		hid.cancelReceiveReport();
		removeFromClientSubscriptions();
		setWorkDone();
	}

	void removeFromClientSubscriptions() const
	{
		auto& subscriptions = static_cast<Socket&>(*sock).custom_data.getStructFromMap(ClientData).subscriptions;
		for (auto i = subscriptions.begin(); i != subscriptions.end(); ++i)
		{
			if (*i == this)
			{
				subscriptions.erase(i);
				break;
			}
		}
	}

	void onTick() final
	{
		SOUP_IF_UNLIKELY (static_cast<Socket&>(*sock).isWorkDoneOrClosed())
		{
			hid.cancelReceiveReport();
		}
		else
		{
			while (auto node = deque.pop_back())
			{
				//std::cout << "received report: " << string::bin2hex(*node) << std::endl;
				ServerWebService::wsSendBin(static_cast<Socket&>(*sock), std::move(*node));
			}
		}

		SOUP_IF_UNLIKELY (!thrd.isRunning())
		{
			std::string msg = "stopped:";
			msg.append(std::to_string(hid_hash));
			ServerWebService::wsSendText(static_cast<Socket&>(*sock), std::move(msg));

			removeFromClientSubscriptions();

			setWorkDone();
		}
	}

	int getSchedulingDisposition() const noexcept final
	{
		return HIGH_FREQUENCY;
	}
};

ReceiveReportsTask* ClientData::findSubscription(uint32_t hid_hash) const noexcept
{
	for (const auto& sub : subscriptions)
	{
		if (sub->hid_hash == hid_hash)
		{
			return sub;
		}
	}
	return nullptr;
}

struct ListDevicesTask : public soup::Task
{
	SharedPtr<Worker> sock;
	Thread thrd;
	std::vector<std::string> msgs;

	ListDevicesTask(SharedPtr<Worker>&& _sock)
		: sock(std::move(_sock)), thrd(&thrd_run, this)
	{
	}

	static void thrd_run(Capture&& cap)
	{
		ListDevicesTask& task = cap.get<ListDevicesTask>();
		for (const auto& hid : hwHid::getAll())
		{
			if (hid_is_permitted(hid))
			{
				std::string& msg = task.msgs.emplace_back("dev:");
				/*  [1] */ msg.append(std::to_string(hid_to_hash(hid))).push_back(':');
				/*  [2] */ msg.append(std::to_string(hid_to_physical_hash(hid))).push_back(':');
				/*  [3] */ msg.append(std::to_string(hid.vendor_id)).push_back(':');
				/*  [4] */ msg.append(std::to_string(hid.product_id)).push_back(':');
				/*  [5] */ msg.append(hid.getProductName()).push_back(':');
				/*  [6] */ msg.append(std::to_string(hid.usage)).push_back(':');
				/*  [7] */ msg.append(std::to_string(hid.usage_page)).push_back(':');
				/*  [8] */ msg.append(std::to_string(hid.input_report_byte_length)).push_back(':');
				/*  [9] */ msg.append(std::to_string(hid.output_report_byte_length)).push_back(':');
				/* [10] */ msg.append(std::to_string(hid.feature_report_byte_length)).push_back(':');
				std::vector<std::string> report_ids{};
				for (unsigned int i = 0; i != 0x100; ++i)
				{
					if (hid.hasReportId(i))
					{
						report_ids.emplace_back(std::to_string(i));
					}
				}
				/* [11] */ msg.append(string::join(report_ids, ','));
			}
		}
	}

	void onTick() final
	{
		if (!thrd.isRunning())
		{
			for (auto& msg : msgs)
			{
				ServerWebService::wsSendText(static_cast<Socket&>(*sock), std::move(msg));
			}
			ServerWebService::wsSendText(static_cast<Socket&>(*sock), "dev");
			setWorkDone();
		}
	}
};

int entry(std::vector<std::string>&& args, bool console)
{
	auto certstore = soup::make_shared<CertStore>();
	{
		X509Certchain certchain;
		SOUP_ASSERT(certchain.fromPem(R"(-----BEGIN CERTIFICATE-----
MIIF/DCCBGSgAwIBAgIQH1nGumKdC869SnXDdjpRizANBgkqhkiG9w0BAQsFADBg
MQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQD
Ey5TZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gQ0EgRFYgUjM2
MB4XDTI1MTAzMTAwMDAwMFoXDTI2MDMwNjIzNTk1OVowGDEWMBQGA1UEAwwNKi5m
YWtldGxzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKZt+8pe
ZABBMSORWDlJBKykSbbNeEX2vPNrsQBqa3aBzQLdp6dm8qw099a5mn/vuQzdtFhc
QbaemxoVViszzM3dpTlOgLyl2r4cr8KMXJ/rRMqLeaYks+BVYJyxKAlVIduJCpP+
cxYUIiz+zNGMucuFdanzeNfCRhakDkzHH/LKZFYDHeqdR8vdUnOH8n9xuGR7sC6I
PbfML8SXCnazMpcPAeIFzJeZW3fbFIQ5R6B7X38k9+wUzKXrJo0+Q8U1mIAsV7fh
4gn+xgrFOJ7T2Vd8EtHgnr5nzNRDk4prE+ecTxBveL4QGuNoPaABtor6OLBR54AQ
8ycj29lQ094BrJcCAwEAAaOCAngwggJ0MB8GA1UdIwQYMBaAFGjAEhYYDq/O9oem
MlejRlFdywcnMB0GA1UdDgQWBBRqYi9dBjbiV9wE6GEtzyzUM6cQmjAOBgNVHQ8B
Af8EBAMCBaAwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDATBJBgNV
HSAEQjBAMDQGCysGAQQBsjEBAgIHMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2Vj
dGlnby5jb20vQ1BTMAgGBmeBDAECATCBhAYIKwYBBQUHAQEEeDB2ME8GCCsGAQUF
BzAChkNodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNTZXJ2ZXJB
dXRoZW50aWNhdGlvbkNBRFZSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2Nz
cC5zZWN0aWdvLmNvbTAlBgNVHREEHjAcgg0qLmZha2V0bHMuY29tggtmYWtldGxz
LmNvbTCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AJaXZL9VWJet90OHaDcIQnfp
8DrV9qTzNm5GpD8PyqnGAAABmjqerq4AAAQDAEcwRQIgY1YdLRDkbq9U9qGLpX5M
IESNpCLFKVgoPLyNQQejtPUCIQCGlFB13fGO7GpVZLXyuOrXIWRZQUxnm1GqhvOP
BoovPgB2ANFuqaVoB35mNaA/N6XdvAOlPEESFNSIGPXpMbMjy5UEAAABmjqerwkA
AAQDAEcwRQIhAMxyLWnCpof354KMPYiWQmqd+2D+yyV5ZL7rmvIJw0ojAiAxxsid
se3hTmdo39MJLKyVqlZKUua5dmLckUYUImsogTANBgkqhkiG9w0BAQsFAAOCAYEA
ByJlO00LMIgL6d5xfouZHl1OL2w0DDiWHQa87BM9AqUFSgE1IsWyUAMTVoxNp3bM
c4fiBoJ9P32hDft2gJRCtJ+xOlU9ufQqCfpN9pBxe8eEldJdnHi7q9Y1dIVwRA+y
xY2r1xgTmjYgv1Uo5mQoOjgvrRdUNTyW0Rkp9+9zr6NFxi4orqypt4KKOFY2DlV9
wKmS4HPXSNR6QEylUR1+IsCP7iQzgTcZDYYLH2vAekJ1vFJkxZyB8a1vjuUxohPi
JoXnOqBu5T9JdE81/Rm01bHQ6XAiAHpQRCyZZ3TBUgpPd10DrV8K/gMuBduKOkgk
BnwNZjOCcCwgI66F5kmoeT95ovn8ApKO9aT3EfYXx3XM+xaWjEQRpXulB9AYjQvg
wxdW+cpHAa/ttPEnrb4y2Az4uYMM2016U5p1o6SP3/feGbWSsJ33OF4VvSaS1x0h
DgzfqIX4/8yeYsfNNsoSpcwV9UGBZ7Zs0Avy1Mm5ah0Z6CGGKVWb7Qqse1YR9MSa
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGTDCCBDSgAwIBAgIQOXpmzCdWNi4NqofKbqvjsTANBgkqhkiG9w0BAQwFADBf
MQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQD
Ey1TZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBSNDYw
HhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBgMQswCQYDVQQGEwJHQjEY
MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdvIFB1Ymxp
YyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gQ0EgRFYgUjM2MIIBojANBgkqhkiG9w0B
AQEFAAOCAY8AMIIBigKCAYEAljZf2HIz7+SPUPQCQObZYcrxLTHYdf1ZtMRe7Yeq
RPSwygz16qJ9cAWtWNTcuICc++p8Dct7zNGxCpqmEtqifO7NvuB5dEVexXn9RFFH
12Hm+NtPRQgXIFjx6MSJcNWuVO3XGE57L1mHlcQYj+g4hny90aFh2SCZCDEVkAja
EMMfYPKuCjHuuF+bzHFb/9gV8P9+ekcHENF2nR1efGWSKwnfG5RawlkaQDpRtZTm
M64TIsv/r7cyFO4nSjs1jLdXYdz5q3a4L0NoabZfbdxVb+CUEHfB0bpulZQtH1Rv
38e/lIdP7OTTIlZh6OYL6NhxP8So0/sht/4J9mqIGxRFc0/pC8suja+wcIUna0HB
pXKfXTKpzgis+zmXDL06ASJf5E4A2/m+Hp6b84sfPAwQ766rI65mh50S0Di9E3Pn
2WcaJc+PILsBmYpgtmgWTR9eV9otfKRUBfzHUHcVgarub/XluEpRlTtZudU5xbFN
xx/DgMrXLUAPaI60fZ6wA+PTAgMBAAGjggGBMIIBfTAfBgNVHSMEGDAWgBRWc1hk
lfmSGrASKgRieaFAFYghSTAdBgNVHQ4EFgQUaMASFhgOr872h6YyV6NGUV3LBycw
DgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMBsGA1UdIAQUMBIwBgYEVR0gADAIBgZngQwBAgEw
VAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdv
UHVibGljU2VydmVyQXV0aGVudGljYXRpb25Sb290UjQ2LmNybDCBhAYIKwYBBQUH
AQEEeDB2ME8GCCsGAQUFBzAChkNodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3Rp
Z29QdWJsaWNTZXJ2ZXJBdXRoZW50aWNhdGlvblJvb3RSNDYucDdjMCMGCCsGAQUF
BzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEA
YtOC9Fy+TqECFw40IospI92kLGgoSZGPOSQXMBqmsGWZUQ7rux7cj1du6d9rD6C8
ze1B2eQjkrGkIL/OF1s7vSmgYVafsRoZd/IHUrkoQvX8FZwUsmPu7amgBfaY3g+d
q1x0jNGKb6I6Bzdl6LgMD9qxp+3i7GQOnd9J8LFSietY6Z4jUBzVoOoz8iAU84OF
h2HhAuiPw1ai0VnY38RTI+8kepGWVfGxfBWzwH9uIjeooIeaosVFvE8cmYUB4TSH
5dUyD0jHct2+8ceKEtIoFU/FfHq/mDaVnvcDCZXtIgitdMFQdMZaVehmObyhRdDD
4NQCs0gaI9AAgFj4L9QtkARzhQLNyRf87Kln+YU0lgCGr9HLg3rGO8q+Y4ppLsOd
unQZ6ZxPNGIfOApbPVf5hCe58EZwiWdHIMn9lPP6+F404y8NNugbQixBber+x536
WrZhFZLjEkhp7fFXf9r32rNPfb74X/U90Bdy4lzp3+X1ukh1BuMxA/EEhDoTOS3l
7ABvc7BYSQubQ2490OcdkIzUh3ZwDrakMVrbaTxUM2p24N6dB+ns2zptWCva6jzW
r8IWKIMxzxLPv5Kt3ePKcUdvkBU/smqujSczTzzSjIoR5QqQA6lN1ZRSnuHIWCvh
JEltkYnTAH41QJ6SAWO66GrrUESwN/cgZzL4JLEqz1Y=
-----END CERTIFICATE-----)"));
		certstore->add(
			std::move(certchain),
			RsaPrivateKey::fromPem(R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmbfvKXmQAQTEj
kVg5SQSspEm2zXhF9rzza7EAamt2gc0C3aenZvKsNPfWuZp/77kM3bRYXEG2npsa
FVYrM8zN3aU5ToC8pdq+HK/CjFyf60TKi3mmJLPgVWCcsSgJVSHbiQqT/nMWFCIs
/szRjLnLhXWp83jXwkYWpA5Mxx/yymRWAx3qnUfL3VJzh/J/cbhke7AuiD23zC/E
lwp2szKXDwHiBcyXmVt32xSEOUege19/JPfsFMyl6yaNPkPFNZiALFe34eIJ/sYK
xTie09lXfBLR4J6+Z8zUQ5OKaxPnnE8Qb3i+EBrjaD2gAbaK+jiwUeeAEPMnI9vZ
UNPeAayXAgMBAAECggEAOYwMJVRwFZp1KExIij5STHPePURc0yxW94CESpWBpQ+K
2PPV1c+GF7+U9v1ki9pTTTyX8HmuCzxaezFngza9GW4LhH49i3153oTCzW2FVZKf
Tb3eiXFldStwZZ3oLxntxCBltPilyLubeZ19KvQTBmmWXvaeEVTOsWN2wluUE3oT
QEEFJmvWSj6Ow5HwA2xZP5dD4gv7nCY1swTePVLgWtJDC3AWDmKv3mB28brmtaDw
wP/Oq9LLlHJDK+AzJEuUs+VDFQi7j6yqXWglSjO3Jwkkfkqg/SSoZ9BKdd6i0DLs
UnUWHHATpv0Lwsa7w8csQBwfskUxsXECZpwzpCgsIQKBgQDYl2wvwjjG6qZtr060
rj4PDkFLxFbtlmBiyW9ShM6iqK6FWQJJ1FNr6MdM2zBqw+n4tldpU3DnuZQphgZK
57jejWFsHH5DYkS8k0k021AYT2IyCFHoEF43LlbRDXQguw1fADnoy6FpJBaRzuxx
jPEHdB/aYqngmTXglFYkizN2BwKBgQDEthR1FV5iPdQXKSR+Yu2irBzpxY1xhdd2
V5082etd2vBvAT7e4k8MroNMuYqL8miu2SeTJEyNkpCVoxQPF4uavandoRuEFIZl
8VPVvG5xqYIqXAJ4XlSImEgUww+jJfyLzHT0TZi6rrdHV/8zUXEimjc6OBZVafDg
FP6Lqo/w8QKBgQCxx3B8rv3tgDNFOqzur0qvDvNXnnv/nfvVeiPO5sW5S52cRJgV
Q5uJqlLUaeGO8Oo+RGTxRhUZjwDnKGRH3XWn7wI1PBoDc0iaRIbFRPK0UYx3Js8c
HTtILdgC1fko2IA8JzJhO6tsYrvHyMHY3mgExzNSDMQFX5ySjw86BawixwKBgBGc
J0qwBgoPdOw53618179HXzNCXz45eCd9AnOPIrX9Qqb9Wo6DfgYpnVGCDrgmlF6K
zDMs/bly1ITA26vaNMI+lnVj1d3GJJ39s76fpteAEEoQgJwb/b9YuqM5Ly4w2WH+
hL3WMIUN3RSC+TKz6MfrPGR23vD4kfrNhlgkhcxRAoGAEb6nXwyWe5hg9+qE2fcf
W27VApoalmnDOGFHtGhUitbBw7mHPb6wsSh4mx5Ucccfb5WUO3Cq5aW3qsDdkM+a
YrBDbvw7PPcAX0vokpyFQvHH35AsIXQuYlQyGzcCdZkpFPIB5gVbLvbgxpBvEbVZ
mGJpw7X/6Pg0ux0Ze11cr2c=
-----END PRIVATE KEY-----)")
		);
	}

	Server serv;
	ServerWebService web_srv;
	web_srv.should_accept_websocket_connection = [](Socket& s, const HttpRequest& req, ServerWebService&)
	{
#if DEBUG || !SOUP_WINDOWS
		return true;
#else
		if (auto origin = req.findHeader("Origin"))
		{
			// Run MessageBoxA off-thread because otherwise explorer freezes if the user confirms the prompt via a keyboard press (enter or spacebar). Can't make this shit up.
			// MB_DEFAULT_DESKTOP_ONLY makes the MessageBox appear on top of other apps, including Firefox, which is good as otherwise the user might be unaware of this prompt.
			static bool res;
			Thread thrd([](Capture&& cap)
			{
				res = (MessageBoxA(0, cap.get<std::string>().c_str(), "WebHID for Firefox", MB_YESNO | MB_DEFAULT_DESKTOP_ONLY) == IDYES);
			}, std::string("Allow the page at " + *origin + " to access your HID devices?"));
			thrd.awaitCompletion();
			return res;
		}
		return false;
#endif
	};
	web_srv.on_websocket_connection_established = [](Socket& s, const HttpRequest& req, ServerWebService&)
	{
		if (req.path == "/r1")
		{
			s.custom_data.getStructFromMap(ClientData).supports_report_ids = true;
		}
		ServerWebService::wsSendText(s, "ver:0.2.2");
	};
	web_srv.on_websocket_message = [](WebSocketMessage& msg, Socket& s, ServerWebService&)
	{
		if (msg.is_text)
		{
			//std::cout << "Text message: " << msg.data << std::endl;
			if (msg.data == "list")
			{
				Scheduler::get()->add<ListDevicesTask>(Scheduler::get()->getShared(s));
			}
			else if (msg.data.substr(0, 4) == "open")
			{
				const uint32_t hid_hash = std::strtoul(msg.data.c_str() + 4, nullptr, 10);
				if (s.custom_data.getStructFromMap(ClientData).findSubscription(hid_hash) == nullptr)
				{
					for (auto& hid : hwHid::getAll())
					{
						if (hid_to_hash(hid) == hid_hash && hid_is_permitted(hid))
						{
							Scheduler::get()->add<ReceiveReportsTask>(Scheduler::get()->getShared(s), std::move(hid), hid_hash);
							break;
						}
					}
				}
			}
			else if (msg.data.substr(0, 4) == "clse")
			{
				const uint32_t hid_hash = std::strtoul(msg.data.c_str() + 4, nullptr, 10);
				if (auto sub = s.custom_data.getStructFromMap(ClientData).findSubscription(hid_hash))
				{
					sub->unsubscribe();
				}
			}
			else if (msg.data.substr(0, 4) == "rcfr")
			{
				uint32_t hid_hash = std::strtoul(msg.data.c_str() + 4, nullptr, 10);
				for (auto& hid : hwHid::getAll())
				{
					if (hid_to_hash(hid) == hid_hash && hid_is_permitted(hid))
					{
						Buffer report;
						try
						{
							hid.receiveFeatureReport(report);
						}
						catch (std::exception&)
						{
						}
						BufferWriter bw;
						uint8_t msgid = 2; bw.u8(msgid);
						bw.u32_be(hid_hash);
						bw.buf.append(report);
						ServerWebService::wsSendBin(s, bw.buf.toString());
						break;
					}
				}
			}
		}
		else
		{
			//std::cout << "Binary message: " << string::bin2hex(msg.data) << std::endl;
			MemoryRefReader r(msg.data);
			uint8_t msgid; r.u8(msgid);
			if (msgid == 0)
			{
				if (msg.data.size() >= 5)
				{
					uint32_t hid_hash; r.u32_be(hid_hash);
					for (auto& hid : hwHid::getAll())
					{
						if (hid_to_hash(hid) == hid_hash && hid_is_permitted(hid))
						{
							Buffer data;
							data.append(msg.data.data() + 5, msg.data.size() - 5);
							//std::cout << "sending report: " << string::bin2hex(data.toString()) << std::endl;
							hid.sendReport(std::move(data));
							break;
						}
					}
				}
			}
			else if (msgid == 1)
			{
				if (msg.data.size() >= 5)
				{
					uint32_t hid_hash; r.u32_be(hid_hash);
					for (auto& hid : hwHid::getAll())
					{
						if (hid_to_hash(hid) == hid_hash && hid_is_permitted(hid))
						{
							Buffer data;
							data.append(msg.data.data() + 5, msg.data.size() - 5);
							//std::cout << "sending feature report: " << string::bin2hex(data.toString()) << std::endl;
							hid.sendFeatureReport(std::move(data));
							break;
						}
					}
				}
			}
		}
	};
	if (!serv.bindCrypto(33881, &web_srv, std::move(certstore)))
	{
#if DEBUG || !SOUP_WINDOWS
		std::cout << "Failed to bind to port 33881." << std::endl;
#else
		MessageBoxA(0, "Failed to bind to port 33881.", "WebHID for Firefox", MB_ICONERROR);
#endif
		return 1;
	}
	std::cout << "Listening on port 33881." << std::endl;
	serv.run();
	return 0;
}

#if DEBUG
SOUP_MAIN_CLI(entry);
#else
SOUP_MAIN_GUI(entry);
#endif
