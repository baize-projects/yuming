import unittest
from unittest.mock import patch

import icp_query


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, payloads):
        self.payloads = list(payloads)

    def get(self, *args, **kwargs):
        return FakeResponse(self.payloads.pop(0))

    def post(self, *args, **kwargs):
        return FakeResponse(self.payloads.pop(0))


class IcpQueryTests(unittest.TestCase):
    def test_generated_domains_start_at_four_chars_across_tlds(self):
        domains = icp_query.build_generated_domains(
            tlds=(".xyz", ".icu", ".top"),
            min_length=4,
            max_length=4,
            limit=5,
            start_after=None,
        )

        self.assertEqual(
            domains,
            ["aaaa.xyz", "aaaa.icu", "aaaa.top", "aaab.xyz", "aaab.icu"],
        )

    def test_generated_domains_can_resume_after_label(self):
        domains = icp_query.build_generated_domains(
            tlds=(".xyz", ".icu"),
            min_length=4,
            max_length=4,
            limit=3,
            start_after="aaaa.xyz",
        )

        self.assertEqual(domains, ["aaab.xyz", "aaab.icu", "aaac.xyz"])

    def test_apicn_day_records_extract_domain_and_history_fields(self):
        records, raw_count = icp_query.parse_apicn_day_records(
            {
                "code": 200,
                "data": {
                    "list": [
                        {
                            "domain": "oldsite.xyz",
                            "company": "示例科技有限公司",
                            "license": "京ICP备12345678号-1",
                            "audit_date": "2024-03-02",
                        },
                        {
                            "domain": "oldsite.xyz",
                            "company": "重复记录会被去重",
                        },
                    ]
                },
            },
            "2024-03-02",
            3,
        )

        self.assertEqual(raw_count, 2)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].domain, "oldsite.xyz")
        self.assertEqual(records[0].provider, "apicn-day")
        self.assertEqual(records[0].icp, "京ICP备12345678号-1")
        self.assertEqual(records[0].unit, "示例科技有限公司")
        self.assertEqual(records[0].approved_at, "2024-03-02")
        self.assertEqual(records[0].raw["source_page"], 3)

    def test_apicn_history_match_keeps_record_when_domain_is_unregistered(self):
        whois_result = icp_query.QueryResult(
            domain="oldsite.xyz",
            status="not_found",
            provider="jyblog-whois-api",
            registered=False,
            error="域名未注册",
        )
        history_result = icp_query.QueryResult(
            domain="oldsite.xyz",
            status="found",
            provider="apicn-day",
            icp="京ICP备12345678号-1",
            unit="示例科技有限公司",
            approved_at="2024-03-02",
        )

        result = icp_query.merge_unregistered_whois_and_history(
            whois_result,
            history_result,
        )

        self.assertEqual(result.status, "found")
        self.assertFalse(result.registered)
        self.assertEqual(result.provider, "jyblog-whois-api+apicn-day")
        self.assertEqual(result.icp, "京ICP备12345678号-1")
        self.assertEqual(result.unit, "示例科技有限公司")
        self.assertIn("whois", result.raw)
        self.assertIn("history", result.raw)

    def test_generate_and_apicn_source_are_mutually_exclusive(self):
        with patch(
            "icp_query.sys.argv",
            ["icp_query.py", "--generate", "--apicn-day-source", "--limit", "1"],
        ):
            self.assertEqual(icp_query.main(), 2)

    def test_jyblog_signature_matches_frontend_sample(self):
        signature = icp_query.generate_jyblog_signature(
            "NjJSU6pjCTgC5G5x",
            1783623440,
        )

        self.assertEqual(
            signature,
            "772b762ef9ec676057b8c08b4dd4e0b150d5ab11c39c6c65690ef53f138d8e06",
        )

    def test_jyblog_api_headers_include_required_signature_fields(self):
        headers = icp_query.build_jyblog_api_headers(
            nonce="NjJSU6pjCTgC5G5x",
            timestamp=1783623440,
        )

        self.assertEqual(headers["nonce"], "NjJSU6pjCTgC5G5x")
        self.assertEqual(headers["timestamp"], "1783623440")
        self.assertEqual(
            headers["signature"],
            "772b762ef9ec676057b8c08b4dd4e0b150d5ab11c39c6c65690ef53f138d8e06",
        )
        self.assertEqual(headers["X-Requested-With"], "XMLHttpRequest")

    def test_jyblog_parses_whois_and_beian(self):
        result = icp_query.parse_jyblog_text(
            "qq.com",
            """
            域名:

            QQ.COM

            注册31年
            已备案
            Whois服务器:

            whois.markmonitor.com

            更新时间:

            5/22/2026, 11:00:17 AM

            注册时间:

            5/4/1995, 12:00:00 PM

            过期时间:

            7/27/2034, 10:09:19 AM

            注册机构:

            MarkMonitor Information Technology (Shanghai) Co., Ltd.

            状态：

            · 客户禁止删除 clientDeleteProhibited

            DNS：

            · NS1.QQ.COM

            备案信息：

            · 域名:

            qq.com

            · 备案主体:

            粤B2-20090059

            · 许可证号:

            粤B2-20090059-5

            · 单位名称:

            深圳市腾讯计算机系统有限公司

            · 单位性质:

            企业

            · 通过时间:

            2026-01-15 11:27:48
            """,
            "完整 WHOIS 信息:\nDomain Name:QQ.COM",
        )

        self.assertEqual(result.provider, "jyblog")
        self.assertEqual(result.status, "found")
        self.assertTrue(result.registered)
        self.assertFalse(result.expired)
        self.assertEqual(result.icp, "粤B2-20090059-5")
        self.assertEqual(result.main_licence, "粤B2-20090059")
        self.assertEqual(result.unit, "深圳市腾讯计算机系统有限公司")
        self.assertEqual(result.expiration_date, "2034-07-27T10:09:19")
        self.assertEqual(result.whois_server, "whois.markmonitor.com")
        self.assertEqual(result.name_servers, ["NS1.QQ.COM"])

    def test_jyblog_parses_registered_without_beian(self):
        result = icp_query.parse_jyblog_text(
            "demo.top",
            """
            域名:

            demo.top

            Whois服务器:

            whois.namecheap.com

            过期时间:

            11/8/2026, 1:14:17 PM

            备案信息：

            · 未找到备案信息
            """,
            "完整 WHOIS 信息:\nDomain Name:demo.top",
        )

        self.assertEqual(result.status, "not_found")
        self.assertTrue(result.registered)
        self.assertEqual(result.error, "未找到备案信息")
        self.assertEqual(result.expiration_date, "2026-11-08T13:14:17")

    def test_jyblog_parses_unregistered_domain(self):
        result = icp_query.parse_jyblog_text(
            "example.xyz",
            """
            域名:

            example.xyz

            未注册
            """,
            "完整 WHOIS 信息:\nThe queried object does not exist:DOMAIN NOT FOUND",
        )

        self.assertEqual(result.status, "not_found")
        self.assertFalse(result.registered)
        self.assertIsNone(result.expired)
        self.assertEqual(result.error, "域名未注册")

    def test_target_merge_marks_unregistered_with_icp_as_found(self):
        whois_result = icp_query.QueryResult(
            domain="oldsite.xyz",
            status="not_found",
            provider="jyblog",
            registered=False,
            error="域名未注册",
        )
        icp_result = icp_query.QueryResult(
            domain="oldsite.xyz",
            status="found",
            provider="apihz",
            icp="京ICP备12345678号-1",
            unit="示例公司",
            site_type="企业",
            approved_at="2025-01-01",
        )

        result = icp_query.merge_unregistered_whois_and_icp(whois_result, icp_result)

        self.assertEqual(result.status, "found")
        self.assertFalse(result.registered)
        self.assertEqual(result.provider, "jyblog+apihz")
        self.assertEqual(result.icp, "京ICP备12345678号-1")
        self.assertEqual(result.unit, "示例公司")
        self.assertIn("whois", result.raw)
        self.assertIn("icp", result.raw)

    def test_target_merge_does_not_match_uncertain_icp_result(self):
        whois_result = icp_query.QueryResult(
            domain="oldsite.xyz",
            status="not_found",
            provider="jyblog",
            registered=False,
            error="域名未注册",
        )
        icp_result = icp_query.QueryResult(
            domain="oldsite.xyz",
            status="unknown",
            provider="apihz",
            error="查询失败或没有备案。",
        )

        result = icp_query.merge_unregistered_whois_and_icp(whois_result, icp_result)

        self.assertEqual(result.status, "unknown")
        self.assertFalse(result.registered)
        self.assertIsNone(result.icp)
        self.assertEqual(result.error, "查询失败或没有备案。")

    def test_target_registered_domain_is_not_a_match_even_with_icp(self):
        whois_result = icp_query.QueryResult(
            domain="qq.com",
            status="found",
            provider="jyblog",
            registered=True,
            expired=False,
            expiration_date="2034-07-27T10:09:19",
            icp="粤B2-20090059-5",
            unit="深圳市腾讯计算机系统有限公司",
        )

        result = icp_query.make_nonmatching_registered_result(whois_result)

        self.assertEqual(result.status, "not_found")
        self.assertTrue(result.registered)
        self.assertEqual(result.icp, "粤B2-20090059-5")
        self.assertEqual(result.error, "域名已注册，不符合未注册目标")

    def test_jyblog_api_beian_detects_record(self):
        result = icp_query.query_jyblog_api_beian(
            FakeSession(
                [
                    {
                        "domain": "qq.com",
                        "mainLicence": "粤B2-20090059",
                        "serviceLicence": "粤B2-20090059-5",
                        "unitName": "深圳市腾讯计算机系统有限公司",
                        "natureName": "企业",
                        "updateRecordTime": "2026-01-15 11:27:48",
                    }
                ]
            ),
            "qq.com",
            timeout=1,
            retries=0,
        )

        self.assertEqual(result.status, "found")
        self.assertEqual(result.provider, "jyblog-api")
        self.assertEqual(result.icp, "粤B2-20090059-5")
        self.assertEqual(result.main_licence, "粤B2-20090059")
        self.assertEqual(result.unit, "深圳市腾讯计算机系统有限公司")
        self.assertEqual(result.approved_at, "2026-01-15 11:27:48")

    def test_jyblog_api_beian_marks_empty_object_as_not_found(self):
        result = icp_query.query_jyblog_api_beian(
            FakeSession([{}]),
            "example.xyz",
            timeout=1,
            retries=0,
        )

        self.assertEqual(result.status, "not_found")
        self.assertEqual(result.provider, "jyblog-api")
        self.assertEqual(result.error, "未找到备案信息")

    def test_jyblog_whois_api_detects_registered_domain(self):
        result = icp_query.parse_jyblog_whois_api(
            "demo.top",
            {
                "Domain Name": "demo.top",
                "Registrar WHOIS Server": "whois.namecheap.com",
                "Registrar": "Namecheap Inc.",
                "Registry Expiry Date": "2026-11-08T05:14:17Z",
                "Domain Status": "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
                "Name Server": "ns1.afternic.com ns2.afternic.com",
            },
        )

        self.assertEqual(result.status, "found")
        self.assertTrue(result.registered)
        self.assertEqual(result.provider, "jyblog-whois-api")
        self.assertEqual(result.expiration_date, "2026-11-08T05:14:17")
        self.assertEqual(result.registrar, "Namecheap Inc.")
        self.assertEqual(result.name_servers, ["ns1.afternic.com", "ns2.afternic.com"])

    def test_jyblog_whois_api_detects_unregistered_domain(self):
        result = icp_query.parse_jyblog_whois_api(
            "example.xyz",
            {"The queried object does not exist": "DOMAIN NOT FOUND"},
        )

        self.assertEqual(result.status, "not_found")
        self.assertFalse(result.registered)
        self.assertEqual(result.error, "域名未注册")

    def test_apihz_detects_icp_with_icp_literal(self):
        result = icp_query.query_apihz(
            FakeSession(
                [
                    {
                        "code": 200,
                        "type": "企业",
                        "icp": "京ICP证030173号-1",
                        "unit": "北京百度网讯科技有限公司",
                        "time": "2019-05-16",
                    }
                ]
            ),
            "http://example.test/api/wangzhan/icp.php",
            "baidu.com",
            timeout=1,
            retries=0,
            api_id="id",
            api_key="key",
        )

        self.assertEqual(result.status, "found")
        self.assertEqual(result.icp, "京ICP证030173号-1")

    def test_apihz_detects_telecom_record_without_icp_literal(self):
        result = icp_query.query_apihz(
            FakeSession(
                [
                    {
                        "code": 200,
                        "type": "企业",
                        "icp": "粤B2-20090059-5",
                        "unit": "深圳市腾讯计算机系统有限公司",
                        "time": "2026-01-15",
                    }
                ]
            ),
            "http://example.test/api/wangzhan/icp.php",
            "qq.com",
            timeout=1,
            retries=0,
            api_id="id",
            api_key="key",
        )

        self.assertEqual(result.status, "found")
        self.assertEqual(result.icp, "粤B2-20090059-5")

    def test_apihz_marks_fake_success_as_unknown(self):
        result = icp_query.query_apihz(
            FakeSession(
                [
                    {
                        "code": 200,
                        "type": "查询失败",
                        "icp": "查询失败",
                        "unit": "查询失败",
                        "time": "查询失败",
                    }
                ]
            ),
            "http://example.test/api/wangzhan/icp.php",
            "demo.top",
            timeout=1,
            retries=0,
            api_id="id",
            api_key="key",
        )

        self.assertEqual(result.status, "unknown")

    def test_apihz_keeps_retry_response_as_error(self):
        result = icp_query.query_apihz(
            FakeSession([{"code": 400, "msg": "失败，请重试！"}]),
            "http://example.test/api/wangzhan/icp.php",
            "demo.top",
            timeout=1,
            retries=0,
            api_id="id",
            api_key="key",
        )

        self.assertEqual(result.status, "error")

    def test_apihz_marks_clear_no_record_as_not_found(self):
        result = icp_query.query_apihz(
            FakeSession([{"code": 400, "msg": "没有备案"}]),
            "http://example.test/api/wangzhan/icp.php",
            "unused-example.xyz",
            timeout=1,
            retries=0,
            api_id="id",
            api_key="key",
        )

        self.assertEqual(result.status, "not_found")

    def test_apihz_retries_rate_limit(self):
        with patch("icp_query.time.sleep", return_value=None):
            result = icp_query.query_apihz(
                FakeSession(
                    [
                        {"code": 400, "s": 1, "msg": "调用频次过快，请1秒后再试"},
                        {
                            "code": 200,
                            "type": "企业",
                            "icp": "京ICP证030173号-1",
                            "unit": "北京百度网讯科技有限公司",
                            "time": "2019-05-16",
                        },
                    ]
                ),
                "http://example.test/api/wangzhan/icp.php",
                "baidu.com",
                timeout=1,
                retries=1,
                api_id="id",
                api_key="key",
            )

        self.assertEqual(result.status, "found")


if __name__ == "__main__":
    unittest.main()
