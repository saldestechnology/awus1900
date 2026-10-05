/* SPDX-License-Identifier: BSD-3-Clause */
/* RTL8814AU userspace driver: public interface. Register names and structures come from the
 * rtw88-derived shim in rtw/ (GPL-2.0 OR BSD-3-Clause, Copyright(c) Realtek Corporation).
 */
#ifndef RTL8814AU_H
#define RTL8814AU_H

#include "rtw/main.h"
#include "rtw/reg.h"
#include "rtw/tx.h"
#include "rtw/phy.h"
#include "rtw/rtw8814a.h"
#include "rtw/rtw8814a_table.h"

#define FW_HDR_SIZE		64
#define RTL_SAE_TOKEN_MAX_LEN	256
#define FW_HDR_CHKSUM_SIZE	8
#define OCPBASE_TXBUF_88XX	0x18780000
#define OCPBASE_DMEM_88XX	0x00200000
#define TX_DESC_SIZE_8814A	40
#define SYS_FUNC_EN_8814A	0xDC
#define ILLEGAL_KEY_GROUP	0xFAAAAA00

/* dev.c */
int  rtl_open(struct rtw_dev *d, u16 vid, u16 pid);
void rtl_close(struct rtw_dev *d);
int  rtl_write_block(struct rtw_dev *d, u32 addr, const void *buf, u16 len);
int  rtl_bulk_out(struct rtw_dev *d, int qsel_ep, const void *buf, int len, int timeout_ms);

/* mac.c */
int  rtl_mac_power_on(struct rtw_dev *d);
void rtl_mac_power_off(struct rtw_dev *d);
int  rtl_read_chip_info(struct rtw_dev *d);
int  rtl_read_efuse(struct rtw_dev *d);

/* fw.c */
int rtl_download_firmware(struct rtw_dev *d, const char *path);

/* hal.c: choose the TX power-limit table before setting a channel for transmission. */
int rtl_set_tx_regulatory_domain(struct rtw_dev *d, enum rtw_regulatory_domains regd);

/* tx.c: sends one broadcast Probe Request on the current primary channel. */
int rtl_send_probe_request(struct rtw_dev *d, const char *ssid);
/* Station protocol TX helpers; these are internal to association/handshake code, not CLI injection. */
int rtl_send_station_management(struct rtw_dev *d, const u8 *frame, size_t frame_len);
int rtl_send_station_data(struct rtw_dev *d, const u8 *frame, size_t frame_len);
int rtl_station_send_open_auth(struct rtw_dev *d, const u8 bssid[ETH_ALEN]);
int rtl_station_send_wpa2_assoc(struct rtw_dev *d, const u8 bssid[ETH_ALEN],
			       const u8 *ssid, size_t ssid_len);
int rtl_station_send_sae_assoc(struct rtw_dev *d, const u8 bssid[ETH_ALEN],
			      const u8 *ssid, size_t ssid_len);
int rtl_station_send_sae_h2e_assoc(struct rtw_dev *d, const u8 bssid[ETH_ALEN],
				  const u8 *ssid, size_t ssid_len);
struct rtl_wpa2_ptk {
	u8 kck[16];
	u8 kek[16];
	u8 tk[16];
};
struct rtl_sae_ctx {
	u8 own_rand[32];
	u8 own_commit_scalar[32];
	u8 own_commit_element[64];
	u8 pwe[64];
	u8 peer_commit_scalar[32];
	u8 peer_commit_element[64];
	u8 kck[32];
	u8 pmk[32];
	u16 send_confirm;
	u16 peer_confirm;
	bool commit_ready;
	bool keys_ready;
};
enum rtl_station_state {
	RTL_STA_IDLE,
	RTL_STA_AUTH_WAIT,
	RTL_STA_SAE_WAIT_COMMIT,
	RTL_STA_SAE_WAIT_CONFIRM,
	RTL_STA_ASSOC_WAIT,
	RTL_STA_KEY_WAIT_M1,
	RTL_STA_KEY_WAIT_M3,
	RTL_STA_CONNECTED,
	RTL_STA_FAILED,
};
struct rtl_station {
	struct rtw_dev *dev;
	u8 bssid[ETH_ALEN];
	u8 ssid[32];
	u8 ssid_len;
	u8 pmk[32];
	struct rtl_wpa2_ptk ptk;
	struct rtl_sae_ctx sae;
	u8 sae_token[RTL_SAE_TOKEN_MAX_LEN];
	u16 sae_token_len;
	bool use_sae;
	bool sae_h2e;
	bool sae_anti_clogging_retried;
	u8 gtk[32];
	u8 gtk_len;
	u8 gtk_key_id;
	bool has_gtk;
	u8 igtk[16];
	u16 igtk_key_id;
	u64 rx_igtk_ipn;
	bool has_igtk;
	bool rx_igtk_ipn_valid;
	u64 rx_mgmt_packet_number;
	bool rx_mgmt_pn_valid;
	u8 anonce[32];
	u8 snonce[32];
	u64 m1_replay;
	u64 m3_replay;
	u64 tx_packet_number;
	u64 rx_packet_number[16];
	bool rx_pn_valid[16];
	u64 rx_group_packet_number[16];
	bool rx_group_pn_valid[16];
	int (*payload_cb)(void *ctx, u16 ethertype, const u8 *payload, size_t len);
	void *payload_cb_ctx;
	enum rtl_station_state state;
	bool have_ptk;
	int error;
};
int rtl_station_init(struct rtl_station *s, struct rtw_dev *d,
		     const u8 bssid[ETH_ALEN], const u8 *ssid, size_t ssid_len,
		     const u8 *passphrase, size_t passphrase_len);
int rtl_station_init_sae(struct rtl_station *s, struct rtw_dev *d,
			 const u8 bssid[ETH_ALEN], const u8 *ssid, size_t ssid_len,
			 const u8 *passphrase, size_t passphrase_len);
int rtl_station_init_sae_h2e(struct rtl_station *s, struct rtw_dev *d,
			     const u8 bssid[ETH_ALEN], const u8 *ssid, size_t ssid_len,
			     const u8 *passphrase, size_t passphrase_len);
int rtl_station_start(struct rtl_station *s);
int rtl_station_receive(struct rtl_station *s, const u8 *frame, size_t frame_len);
void rtl_station_clear(struct rtl_station *s);
int rtl_station_send_ethernet(struct rtl_station *s, const u8 destination[ETH_ALEN],
			     u16 ethertype, const u8 *payload, size_t len);

/* DHCPv4 client carried over an established station link. IPv4 values are byte arrays. */
enum rtl_dhcp_state {
	RTL_DHCP_IDLE,
	RTL_DHCP_WAIT_OFFER,
	RTL_DHCP_WAIT_ACK,
	RTL_DHCP_BOUND,
	RTL_DHCP_RENEWING,
	RTL_DHCP_FAILED,
};
struct rtl_dhcp_client {
	struct rtl_station *station;
	enum rtl_dhcp_state state;
	u32 xid;
	u8 address[4];
	u8 netmask[4];
	u8 gateway[4];
	u8 dns[4];
	u8 server[4];
	u32 lease_seconds;
	u64 lease_started;
	u64 renew_at;
	u64 expires_at;
	u64 retry_at;
	unsigned retries;
	int error;
};
int rtl_dhcp_start(struct rtl_dhcp_client *client, struct rtl_station *station);
int rtl_dhcp_receive(struct rtl_dhcp_client *client, const u8 *packet, size_t len);
int rtl_dhcp_tick(struct rtl_dhcp_client *client);

/* macOS utun IPv4 packet transport and opt-in interface/route setup. */
struct rtl_utun {
	int fd;
	char ifname[32];
	bool configured;
	bool default_route_changed;
	char previous_gateway[16];
	char previous_ifname[32];
	bool previous_default_interface;
	bool system_dns_changed;
	char dns_service[128];
	char previous_dns[16][46];
	size_t previous_dns_count;
	bool previous_dns_automatic;
	char session_dns[46];
};
int rtl_utun_open(struct rtl_utun *utun);
int rtl_utun_configure(struct rtl_utun *utun, const struct rtl_dhcp_client *dhcp,
		       bool default_route, const char *dns_service);
int rtl_utun_refresh_dns(struct rtl_utun *utun, const struct rtl_dhcp_client *dhcp);
int rtl_utun_read_ipv4(struct rtl_utun *utun, u8 *packet, size_t capacity,
		       size_t *packet_len);
int rtl_utun_write_ipv4(struct rtl_utun *utun, const u8 *packet, size_t packet_len);
void rtl_utun_close(struct rtl_utun *utun);

/* bss.c: parse a beacon or Probe Response including its 4-byte FCS. */
struct rtl_bss_info {
	u8 bssid[ETH_ALEN];
	u8 ssid[32];
	u8 ssid_len;
	u8 channel;
	s32 signal_dbm;
	bool privacy;
	bool rsn_present;
	bool rsn_ccmp;
	bool rsn_psk;
	bool rsn_sae;
	bool rsnxe_sae_h2e;
	bool wpa_vendor;
};
int rtl_parse_bss(const u8 *frame, size_t len, u8 tuned_channel, s32 signal_dbm,
		  struct rtl_bss_info *out);

/* wpa.c: WPA2-PSK key derivation and software CCMP (AES-CCM, 8-byte MIC). */
int rtl_wpa2_derive_pmk(const u8 *passphrase, size_t passphrase_len,
		       const u8 *ssid, size_t ssid_len, u8 pmk[32]);
int rtl_wpa2_derive_ptk(const u8 pmk[32], const u8 addr1[ETH_ALEN],
		       const u8 addr2[ETH_ALEN], const u8 nonce1[32],
		       const u8 nonce2[32], struct rtl_wpa2_ptk *ptk);
int rtl_wpa2_eapol_mic(const u8 kck[16], const u8 *eapol, size_t eapol_len,
		       size_t mic_offset, u8 mic[16]);
int rtl_wpa2_unwrap_key_data(const u8 kek[16], const u8 *wrapped,
			     size_t wrapped_len, u8 *plaintext,
			     size_t plaintext_capacity, size_t *plaintext_len);
int rtl_wpa3_derive_ptk(const u8 pmk[32], const u8 addr1[ETH_ALEN],
		       const u8 addr2[ETH_ALEN], const u8 nonce1[32],
		       const u8 nonce2[32], struct rtl_wpa2_ptk *ptk);
int rtl_wpa3_eapol_mic(const u8 kck[16], const u8 *eapol, size_t eapol_len,
		      size_t mic_offset, u8 mic[16]);
int rtl_wpa3_aes_cmac(const u8 key[16], const u8 *data, size_t data_len,
		      u8 mic[16]);
int rtl_sae_init(struct rtl_sae_ctx *sae, const u8 own_addr[ETH_ALEN],
		 const u8 peer_addr[ETH_ALEN], const u8 *password,
		 size_t password_len);
int rtl_sae_init_h2e(struct rtl_sae_ctx *sae, const u8 own_addr[ETH_ALEN],
		     const u8 peer_addr[ETH_ALEN], const u8 *ssid, size_t ssid_len,
		     const u8 *password, size_t password_len);
int rtl_sae_build_commit(const struct rtl_sae_ctx *sae, u8 *out,
		 size_t capacity, size_t *out_len);
int rtl_sae_build_commit_with_token(const struct rtl_sae_ctx *sae,
				    const u8 *token, size_t token_len,
				    u8 *out, size_t capacity, size_t *out_len);
int rtl_sae_process_commit(struct rtl_sae_ctx *sae, const u8 *body,
			   size_t body_len, u8 *confirm,
			   size_t confirm_capacity, size_t *confirm_len);
int rtl_sae_check_confirm(struct rtl_sae_ctx *sae, const u8 *confirm,
			  size_t confirm_len);
int rtl_ccmp_encrypt(const u8 tk[16], const u8 *mac_header, size_t header_len,
		     u8 tid, u8 key_id, u64 packet_number, const u8 *plaintext,
		     size_t plaintext_len, u8 *out, size_t out_capacity,
		     size_t *out_len);
int rtl_ccmp_decrypt(const u8 tk[16], const u8 *mac_header, size_t header_len,
		     u8 tid, u8 expected_key_id, const u8 *ccmp_payload,
		     size_t ccmp_payload_len, u8 *plaintext, size_t plaintext_capacity,
		     size_t *plaintext_len, u64 *packet_number);

/* rx.c */
struct pcap_out;
struct rtl_rx_stats {
	unsigned frames, crc_err, c2h, bad;
	void (*cb)(void *ctx, const struct rtw_rx_pkt_stat *ps, const u8 *frame, int len);
	void *cb_ctx;
};
void rtl_rx_monitor_enable(struct rtw_dev *d, bool accept_bad_fcs);
void rtl_pcap_open(struct pcap_out **po, const char *path);
void rtl_pcap_close(struct pcap_out *o);
int  rtl_rx_poll(struct rtw_dev *d, struct pcap_out *po, struct rtl_rx_stats *st, int timeout_ms);

/* hal.c */
int  rtl_hw_init(struct rtw_dev *d, const char *fw_path);
bool rtl_channel_is_supported(u8 channel);
int  rtl_set_channel(struct rtw_dev *d, u8 channel, u8 bw);
int  rtl_set_channel_bw(struct rtw_dev *d, u8 primary, u8 bw, bool upper40);
void rtl_prepare_rfk(struct rtw_dev *d);
void rtl_thermal_track_enable(struct rtw_dev *d, bool enable);
void rtl_thermal_track_tick(struct rtw_dev *d);
int rtl_usb3_request_switch(struct rtw_dev *d);
int rtl_read8_checked(struct rtw_dev *d, u32 addr, u8 *value);
int rtl_write8_checked(struct rtw_dev *d, u32 addr, u8 value);

#endif
