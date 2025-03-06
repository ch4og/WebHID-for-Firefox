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
			const Buffer& report = (task.report_ids ? task.hid.receiveReportWithReportId() : task.hid.receiveReportWithoutReportId());
			SOUP_IF_UNLIKELY (report.empty())
			{
				//std::cout << "received empty report for " << task.hid_hash << std::endl;
				break;
			}
			//std::cout << "received report for " << task.hid_hash << std::endl;
			BufferWriter bw;
			uint8_t msgid = (task.report_ids ? 1 : 0); bw.u8(msgid);
			bw.u32be(task.hid_hash);
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
MIIGMDCCBRigAwIBAgIQX4800cgswlDH/QexMSnnnjANBgkqhkiG9w0BAQsFADCB
jzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQD
Ey5TZWN0aWdvIFJTQSBEb21haW4gVmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENB
MB4XDTI1MDMwNjAwMDAwMFoXDTI2MDMwNjIzNTk1OVowGDEWMBQGA1UEAwwNKi5m
YWtldGxzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMe42XWK
HJuR7doFTX79zrEKfTlD2hjRIif3dHKJNTJNvZa52mIoHelP7RVUuFOhp7aZCNLh
IEzDyZObl8vwO6L2PVu5tbBEEoNixbpfhc8ZICEBuVo2UAhnJFcMJtuvtrCq+7ye
oczM/k/nh8FBz2WnLzWs4CZt1sa5knZXFmBmsHJQtQIC6vx7QzVcKGOlAosIEHSK
X4nIz5fLgWSzor1Gay56j31PTk+qRvlPQM2aKiLWnlLfRED4zHJqLe94itu8llPX
b6g+cLxxRKUpMqtG/15cDdBZwv40Dja7bmNfe1u4w2QCVLjvHVaVpNXbcRay/Mhn
M1w5LzDZmV58b18CAwEAAaOCAvwwggL4MB8GA1UdIwQYMBaAFI2MXsRUrYrhd+mb
+ZsF4bgBjWHhMB0GA1UdDgQWBBS6/x/N38wMJrQq/cE1oIcRERMonTAOBgNVHQ8B
Af8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwSQYDVR0gBEIwQDA0BgsrBgEEAbIxAQICBzAlMCMGCCsGAQUFBwIBFhdo
dHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZngQwBAgEwgYQGCCsGAQUFBwEBBHgw
djBPBggrBgEFBQcwAoZDaHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUlNB
RG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZlckNBLmNydDAjBggrBgEFBQcwAYYX
aHR0cDovL29jc3Auc2VjdGlnby5jb20wJQYDVR0RBB4wHIINKi5mYWtldGxzLmNv
bYILZmFrZXRscy5jb20wggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB2AJaXZL9V
WJet90OHaDcIQnfp8DrV9qTzNm5GpD8PyqnGAAABlWsz5fgAAAQDAEcwRQIgTN7Y
/mDqiD3RbGVLEOQK2wvXsboBolBRwGJFuFEsDScCIQCQ0qfb/0V8qqSxrkx/PiVS
1lSn5gBEnQUiQOkefcnW0gB2ABmG1Mcoqm/+ugNveCpNAZGqzi1yMQ+uzl1wQS0l
TMfUAAABlWsz5dAAAAQDAEcwRQIhAJnQJyrSCWWdi9Kyoa7XuMGyDKt183jJMY0E
71abTuBOAiBC+WnK1esG6xr8aVGHRcc+1U/I7LiaG3LCRMYtCKrTGwB2AMs49xWJ
fIShRF9bwd37yW7ymlnNRwppBYWwyxTDFFjnAAABlWsz5f4AAAQDAEcwRQIhAJUs
4PWDwyQJnCxCyEwFlFUY2uYQkGrQPA9f9Sw5Xk1fAiB63eQtZQGjvzvhOghy6z9a
8oGYbDfDQ/zfisMYO7rM6zANBgkqhkiG9w0BAQsFAAOCAQEAEHnSoeBbWiK3CS3a
px0BL+YXxRxdUcTMHgn5o+LlI9sWlpf+JLXmn7Z4QA6fAwT4k/Ue7xsmIq0OraDk
/pEVXWm1HO/9wUkGQg0DBi77BpfHircd7OWIMdt250Q8UAmZkOyhVgnwBcScqMwq
2T5CPaYvYGgYWx/qkIBv7JqhVbrP82rnF9b9ZUZ8GIE31chBmtMva9AsnAN5dmRw
81bVvPWXUfX30CYu5sxeWL06Zpy9nfJumxZri1SWXNTBjSvud2jsZ8tSCUAWLL/4
ui3Vien9m2oMOpaA8xbS88ZTk9Alm/o5febEKJZUPlytQzij8gQpiovFw2v+Cdei
+tFXKw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGEzCCA/ugAwIBAgIQfVtRJrR2uhHbdBYLvFMNpzANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTgx
MTAyMDAwMDAwWhcNMzAxMjMxMjM1OTU5WjCBjzELMAkGA1UEBhMCR0IxGzAZBgNV
BAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UE
ChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdvIFJTQSBEb21haW4g
VmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA1nMz1tc8INAA0hdFuNY+B6I/x0HuMjDJsGz99J/LEpgPLT+N
TQEMgg8Xf2Iu6bhIefsWg06t1zIlk7cHv7lQP6lMw0Aq6Tn/2YHKHxYyQdqAJrkj
eocgHuP/IJo8lURvh3UGkEC0MpMWCRAIIz7S3YcPb11RFGoKacVPAXJpz9OTTG0E
oKMbgn6xmrntxZ7FN3ifmgg0+1YuWMQJDgZkW7w33PGfKGioVrCSo1yfu4iYCBsk
Haswha6vsC6eep3BwEIc4gLw6uBK0u+QDrTBQBbwb4VCSmT3pDCg/r8uoydajotY
uK3DGReEY+1vVv2Dy2A0xHS+5p3b4eTlygxfFQIDAQABo4IBbjCCAWowHwYDVR0j
BBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFI2MXsRUrYrhd+mb
+ZsF4bgBjWHhMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAbBgNVHSAEFDASMAYGBFUdIAAw
CAYGZ4EMAQIBMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9jcmwudXNlcnRydXN0
LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDB2Bggr
BgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQudXNlcnRydXN0LmNv
bS9VU0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAlBggrBgEFBQcwAYYZaHR0cDov
L29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAMr9hvQ5Iw0/H
ukdN+Jx4GQHcEx2Ab/zDcLRSmjEzmldS+zGea6TvVKqJjUAXaPgREHzSyrHxVYbH
7rM2kYb2OVG/Rr8PoLq0935JxCo2F57kaDl6r5ROVm+yezu/Coa9zcV3HAO4OLGi
H19+24rcRki2aArPsrW04jTkZ6k4Zgle0rj8nSg6F0AnwnJOKf0hPHzPE/uWLMUx
RP0T7dWbqWlod3zu4f+k+TY4CFM5ooQ0nBnzvg6s1SQ36yOoeNDT5++SR2RiOSLv
xvcRviKFxmZEJCaOEDKNyJOuB56DPi/Z+fVGjmO+wea03KbNIaiGCpXZLoUmGv38
sbZXQm2V0TP2ORQGgkE49Y9Y3IBbpNV9lXj9p5v//cWoaasm56ekBYdbqbe4oyAL
l6lFhd2zi+WJN44pDfwGF/Y4QA5C5BIG+3vzxhFoYt/jmPQT2BVPi7Fp2RBgvGQq
6jG35LWjOhSbJuMLe/0CjraZwTiXWTb2qHSihrZe68Zk6s+go/lunrotEbaGmAhY
LcmsJWTyXnW0OMGuf1pGg+pRyrbxmRE1a6Vqe8YAsOf4vmSyrcjC8azjUeqkk+B5
yOGBQMkKW+ESPMFgKuOXwIlCypTPRpgSabuY0MLTDXJLR27lk8QyKGOHQ+SwMj4K
00u/I5sUKUErmgQfky3xxzlIPK1aEn8=
-----END CERTIFICATE-----)"));
		certstore->add(
			std::move(certchain),
			RsaPrivateKey::fromPem(R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHuNl1ihybke3a
BU1+/c6xCn05Q9oY0SIn93RyiTUyTb2WudpiKB3pT+0VVLhToae2mQjS4SBMw8mT
m5fL8Dui9j1bubWwRBKDYsW6X4XPGSAhAblaNlAIZyRXDCbbr7awqvu8nqHMzP5P
54fBQc9lpy81rOAmbdbGuZJ2VxZgZrByULUCAur8e0M1XChjpQKLCBB0il+JyM+X
y4Fks6K9Rmsueo99T05Pqkb5T0DNmioi1p5S30RA+Mxyai3veIrbvJZT12+oPnC8
cUSlKTKrRv9eXA3QWcL+NA42u25jX3tbuMNkAlS47x1WlaTV23EWsvzIZzNcOS8w
2ZlefG9fAgMBAAECggEAT1Tti/LASks8300b60WFxG0WMJjzGMh5eMaiSpyVtNWM
aUKJrFOjDfnhgoeUcCPWKoG/L4Sc/+EFQMydDzTte120IasysEFZ2TZytAUdcZXZ
XUMCDQNl5vCRTsJU7Q5u0t4YAGRCgMcsfTDKi8lISGiQKBHzN1CJ74Xm13rgOInd
lAc0wd5S89sL6RYmRTj1LvuZ95EHXHqQGdv0fIFEyP3pF1iPwcoTuIVEeICqnEvW
vd8CVO68eH3HFIwioqjp4qW3pxPZMhVq4161805uAMkoQlE+7MtEVenmP++1u1gM
FjvAs3j9CZqOHZKcLlOtcGSwDlD++fCMMT4slLgLgQKBgQDy58E5nuYXdxlFQQk4
QccUKpyJ2aVXyp9xvTFBot/5Pik1SkuDzv2XU1OTxdxf3EongLy91nMJ2/6/39Je
lf0/2MjzCtJ/lSzZ/zpJAu86UkBkWBAA5loGIof6OKedbEIgqpJqtK59S+j3ExO9
eqa+uFrtt1UfaJG4A7TT+dIvIwKBgQDSfSOdSM5Dh3KsQHVnIWcIkzwTtlJlO+rG
6rDEADxw6Kp8VIL/dq4Foe8yW4VqLVrWUuZsU6jzC9GdnyYi6VaqZ/iSUtGkBMOT
WTTYhqXlURaQ13jhqdwCZJRbVI72JbXn2OGEv8DgXnk//QKED/8VdKqAzCSr1t1f
3yfwei0AlQKBgD19KU66yKg7/+umEP1quUiDmOjUbaSRqFcUe3mQD356m9ffnMob
BdrevxNzTNv/Wc4yKpUryic+x3gu4oQLF/annAbaQHsHejkdANYmpgRvedls6XAw
360Z5K4U1WlmVD8Mrs/QOTOCmdChxad7euZgqLPwat3ujKS2W3oljW1dAoGBAM4/
AB6lsDZLCfnuTxt2h1bHrh5CkAnR5AJ1BC+Ja6/WyvZ4eMOIroumWJKnStr3BgLr
yAxtDSbZddNUljGvIdRnfBEkRXbJlDlVN4rSpMtF4S6bcz7rCUDu/M9g05Qs70j2
IkPJAFzZNUWVzFlKs096uXbqkSQvrUq7ho8DqAThAoGBAL7Nrbr5LWcBgvwEhEla
VRfYb0FUrDwLIrVWntJjW566/pVQQ4BmatsblLjlQYWk9MCIYXWZbnB+2fRx9yjQ
Adggez7Dws/Mrh/wVudKgayHCy5Lgd8rYjNgC+VZf8XGrWX3QXMJ6UWAyQLTeoO7
hToW9o9CQMIhaR43G8di1kjF
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
		ServerWebService::wsSendText(s, "ver:0.2.0");
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
						bw.u32be(hid_hash);
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
					uint32_t hid_hash; r.u32be(hid_hash);
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
					uint32_t hid_hash; r.u32be(hid_hash);
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
