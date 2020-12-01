/*
 * Copyright (C) 2012 Andrew Duggan
 * Copyright (C) 2012 Synaptics Inc.
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#include "fu-chunk.h"
#include "fu-common.h"
#include "fu-synaptics-rmi-device.h"
#include "fu-synaptics-rmi-firmware.h"
#include "fu-synaptics-rmi-v5-device.h"
#include "fwupd-error.h"

#define RMI_F34_BLOCK_SIZE_OFFSET			1
#define RMI_F34_FW_BLOCKS_OFFSET			3
#define RMI_F34_CONFIG_BLOCKS_OFFSET			5

#define RMI_V5_FLASH_CMD_ERASE_WAIT_MS			(5 * 1000)	/* ms */

static gboolean
fu_synaptics_rmi_v5_device_erase_all (FuSynapticsRmiDevice *self, GError **error)
{
	FuSynapticsRmiFunction *f34;
	FuSynapticsRmiFlash *flash = fu_synaptics_rmi_device_get_flash (self);
	g_autoptr(GByteArray) erase_cmd = g_byte_array_new ();

	/* f34 */
	f34 = fu_synaptics_rmi_device_get_function (self, 0x34, error);
	if (f34 == NULL)
		return FALSE;

	/* all other versions */
	fu_byte_array_append_uint8 (erase_cmd, RMI_V5_FLASH_CMD_ERASE_ALL);
	if (!fu_synaptics_rmi_device_write (self,
					    flash->status_addr,
					    erase_cmd,
					    error)) {
		g_prefix_error (error, "failed to erase core config: ");
		return FALSE;
	}
	g_usleep (1000 * RMI_V5_FLASH_CMD_ERASE_WAIT_MS);
	if (!fu_synaptics_rmi_device_enter_backdoor (self, error)) {
		g_prefix_error (error, "failed to enable backdoor: ");
		return FALSE;
	}
	if (!fu_synaptics_rmi_device_wait_for_idle (self,
						    RMI_V5_FLASH_CMD_ERASE_WAIT_MS,
						    RMI_DEVICE_WAIT_FOR_IDLE_FLAG_REFRESH_F34,
						    error)) {
		g_prefix_error (error, "failed to wait for idle for erase: ");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_synaptics_rmi_v5_device_write_block (FuSynapticsRmiDevice *self,
					guint8 cmd,
					guint32 address,
					const guint8 *data,
					gsize datasz,
					GError **error)
{
	g_autoptr(GByteArray) req = g_byte_array_new ();

	g_byte_array_append (req, data, datasz);
	fu_byte_array_append_uint8 (req, cmd);
	if (!fu_synaptics_rmi_device_write (self, address, req, error)) {
		g_prefix_error (error, "failed to write block @0x%x: ", address);
		return FALSE;
	}
	if (!fu_synaptics_rmi_device_wait_for_idle (self,
						    RMI_F34_IDLE_WAIT_MS,
						    RMI_DEVICE_WAIT_FOR_IDLE_FLAG_NONE,
						    error)) {
		g_prefix_error (error, "failed to wait for idle @0x%x: ", address);
		return FALSE;
	}
	return TRUE;
}

gboolean
fu_synaptics_rmi_v5_device_secure_check (FuDevice *device,
					 FuFirmware *firmware,
					 GError **error)
{
	FuSynapticsRmiDevice *self = FU_SYNAPTICS_RMI_DEVICE (device);
	FuSynapticsRmiFirmware *rmi_firmware = FU_SYNAPTICS_RMI_FIRMWARE (firmware);
	FuSynapticsRmiFunction *f34;
	const guint8 *fwbuf;
	const guint8 *signature_dump;
	gnutls_datum_t hash;
	gnutls_datum_t m;
	gnutls_datum_t e;
	gnutls_datum_t sig;
	gnutls_hash_hd_t sha2;
	gnutls_pubkey_t pub;
	gint ec;
	gsize sz;
	guint16 rsa_pubkey_len = fu_synaptics_rmi_device_get_rsa_keylen (self) / 8;
	guint16 rsa_block_cnt = rsa_pubkey_len / 3;
	guint16 rsa_block_remain = rsa_pubkey_len % 3;
	guint32 signature_length = fu_synaptics_rmi_firmware_get_signature_size (rmi_firmware);
	guint32 firmware_length = fu_synaptics_rmi_firmware_get_firmware_size (rmi_firmware) - signature_length;
	guint8 exponent[] = { 1, 0, 1 };
	guint8 *hash_data = NULL;
	unsigned hash_length = gnutls_hash_get_len (GNUTLS_DIG_SHA256);
	g_autoptr(GBytes) bytes_bin = NULL;
	g_autoptr(GBytes) signature = NULL;
	g_autoptr(GBytes) bytes_new = NULL;
	g_autoptr(GByteArray) rsadump = g_byte_array_new ();
	g_autoptr(GByteArray) rsaseg = NULL;

	bytes_bin = fu_firmware_get_image_by_id_bytes (firmware, "ui", error);
	if (bytes_bin == NULL)
		return FALSE;
	bytes_new = g_bytes_new_from_bytes (bytes_bin, 0, firmware_length);
	fwbuf = g_bytes_get_data (bytes_new, &sz);

	/* Parsing signature */
	signature = g_bytes_new_from_bytes (bytes_bin, firmware_length, signature_length);
	sig.size = g_bytes_get_size (signature);
	sig.data = gnutls_malloc (sig.size);
	memcpy (sig.data, g_bytes_get_data (signature, NULL), sig.size);

	signature_dump = g_bytes_get_data (signature, &sz);

	fu_common_dump_full (G_LOG_DOMAIN, "Signature",
			     signature_dump, sz,
			     16, FU_DUMP_FLAGS_NONE);

	f34 = fu_synaptics_rmi_device_get_function (self, 0x34, error);
	if (f34 == NULL)
		return FALSE;

	/* Parsing RSA public key modulus */
	g_debug ("Start to parsing RSA public key");
	if (rsa_block_remain)
		rsa_block_cnt += 1;
	for(guint16 block_num = 0; block_num < rsa_block_cnt ; block_num++){
		g_autoptr(GByteArray) rsa_publickey_seg;
		rsa_publickey_seg = fu_synaptics_rmi_device_read_packet_register (self,
										f34->query_base + 14, // addr of flash properties + 5
										0x3,
										error);
		if (rsa_block_remain && ((block_num + 1) == rsa_block_cnt)) {
			rsa_publickey_seg = g_byte_array_remove_range (rsa_publickey_seg,
									rsa_block_remain,
									rsa_publickey_seg->len - rsa_block_remain);
		}
		for (guint i = 0 ; i < rsa_publickey_seg->len / 2 ; i++) {
			guint8 tmp = rsa_publickey_seg->data[i];
			rsa_publickey_seg->data[i] = rsa_publickey_seg->data[rsa_publickey_seg->len - i - 1];
			rsa_publickey_seg->data[rsa_publickey_seg->len - i - 1] = tmp;
		}
		if (rsa_block_remain && ((block_num + 1) == rsa_block_cnt)) {
			g_byte_array_prepend (rsadump, rsa_publickey_seg->data, rsa_block_remain);
		} else {
			g_byte_array_prepend (rsadump, rsa_publickey_seg->data, rsa_publickey_seg->len);
		}
	}

	fu_common_dump_full (G_LOG_DOMAIN, "RSA public key",
			     rsadump->data, rsadump->len,
			     16, FU_DUMP_FLAGS_NONE);

	/* sanity check size */
	if (rsa_pubkey_len != rsadump->len) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "RSA public key length did not match: %u != %u: ",
			     rsa_pubkey_len, rsadump->len);
		return FALSE;
	}

	/* hash firmware data */
	hash_data = gnutls_malloc (hash_length);
	gnutls_hash_init (&sha2, GNUTLS_DIG_SHA256);
	gnutls_hash (sha2, fwbuf, firmware_length);
	gnutls_hash_deinit (sha2, hash_data);
	/* assign to gnutls_datum_t */
	hash.size = hash_length;
	hash.data = gnutls_malloc (hash.size);
	memcpy (hash.data, hash_data, hash.size);

	gnutls_pubkey_init (&pub);
	/* modulus */
	m.size = rsadump->len;
	m.data = rsadump->data;
	/* exponent */
	e.size = sizeof (exponent);
	e.data = exponent;

	ec = gnutls_pubkey_import_rsa_raw (pub, &m, &e);
	if (ec < 0) {
		g_prefix_error (error, "failed to import RSA key: ");
		return FALSE;
	}
	ec = gnutls_pubkey_verify_hash2 (pub,
					 GNUTLS_SIGN_RSA_SHA256,
					 0,
					 &hash,
					 &sig);
	if (ec < 0) {
		g_prefix_error (error, "failed to verify firmware: ");
		return FALSE;
	}
	g_debug ("RSA verify successful");
	return TRUE;
}

gboolean
fu_synaptics_rmi_v5_device_write_firmware (FuDevice *device,
					   FuFirmware *firmware,
					   FwupdInstallFlags flags,
					   GError **error)
{
	FuSynapticsRmiDevice *self = FU_SYNAPTICS_RMI_DEVICE (device);
	FuSynapticsRmiFlash *flash = fu_synaptics_rmi_device_get_flash (self);
	FuSynapticsRmiFunction *f34;
	FuSynapticsRmiFirmware *rmi_firmware = FU_SYNAPTICS_RMI_FIRMWARE (firmware);
	guint32 address;
	g_autoptr(GBytes) bytes_bin = NULL;
	g_autoptr(GBytes) bytes_cfg = NULL;
	g_autoptr(GBytes) firmware_bin = NULL;
	g_autoptr(GBytes) signature_bin = NULL;
	g_autoptr(GPtrArray) chunks_bin = NULL;
	g_autoptr(GPtrArray) chunks_cfg = NULL;
	g_autoptr(GPtrArray) chunks_sig = NULL;
	g_autoptr(GByteArray) req_addr = g_byte_array_new ();
	guint32 signature_sz = fu_synaptics_rmi_firmware_get_signature_size (rmi_firmware);
	guint32 firmware_sz = fu_synaptics_rmi_firmware_get_firmware_size (rmi_firmware) - signature_sz;

	/* we should be in bootloader mode now, but check anyway */
	if (!fu_device_has_flag (device, FWUPD_DEVICE_FLAG_IS_BOOTLOADER)) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "not bootloader, perhaps need detach?!");
		return FALSE;
	}

	if (!fu_synaptics_rmi_device_enter_backdoor (self, error)) {
		g_prefix_error (error, "failed to enable backdoor: ");
		return FALSE;
	}

	/* check is idle */
	if (!fu_synaptics_rmi_device_wait_for_idle (self, 0,
						    RMI_DEVICE_WAIT_FOR_IDLE_FLAG_REFRESH_F34,
						    error)) {
		g_prefix_error (error, "not idle: ");
		return FALSE;
	}
	if (fu_synaptics_rmi_firmware_get_signature_size (rmi_firmware) == 0 &&
	    fu_synaptics_rmi_device_get_rsa_keylen (self) != 0) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "firmware not secure");
		return FALSE;
	}
	if (fu_synaptics_rmi_firmware_get_signature_size (rmi_firmware) != 0 &&
	    fu_synaptics_rmi_device_get_rsa_keylen (self) == 0) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "device not secure");
		return FALSE;
	}
	g_debug ("all secure");

	/* f34 */
	f34 = fu_synaptics_rmi_device_get_function (self, 0x34, error);
	if (f34 == NULL)
		return FALSE;

	/* get both images */
	bytes_bin = fu_firmware_get_image_by_id_bytes (firmware, "ui", error);
	if (bytes_bin == NULL)
		return FALSE;
	firmware_bin = g_bytes_new_from_bytes (bytes_bin, 0, firmware_sz);
	if (signature_sz != 0)
		signature_bin = g_bytes_new_from_bytes (bytes_bin, firmware_sz, signature_sz);
	bytes_cfg = fu_firmware_get_image_by_id_bytes (firmware, "config", error);
	if (bytes_cfg == NULL)
		return FALSE;

	if (!fu_synaptics_rmi_v5_device_secure_check (device, firmware, error)) {
		g_prefix_error (error, "secure check failed: ");
		return FALSE;
	}
	g_debug ("pass secure check");

	/* disable powersaving */
	if (!fu_synaptics_rmi_device_disable_sleep (self, error)) {
		g_prefix_error (error, "failed to disable sleep: ");
		return FALSE;
	}

	/* unlock again */
	if (!fu_synaptics_rmi_device_write_bootloader_id (self, error)) {
		g_prefix_error (error, "failed to unlock again: ");
		return FALSE;
	}

	/* erase all */
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_ERASE);
	if (!fu_synaptics_rmi_v5_device_erase_all (self, error)) {
		g_prefix_error (error, "failed to erase all: ");
		return FALSE;
	}

	/* write initial address */
	fu_byte_array_append_uint16 (req_addr, 0x0, G_LITTLE_ENDIAN);
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_WRITE);
	if (!fu_synaptics_rmi_device_write (self, f34->data_base, req_addr, error)) {
		g_prefix_error (error, "failed to write 1st address zero: ");
		return FALSE;
	}

	/* write each block */
	if (f34->function_version == 0x01)
		address = f34->data_base + RMI_F34_BLOCK_DATA_V1_OFFSET;
	else
		address = f34->data_base + RMI_F34_BLOCK_DATA_OFFSET;
	chunks_bin = fu_chunk_array_new_from_bytes (firmware_bin,
						    0x00,	/* start addr */
						    0x00,	/* page_sz */
						    flash->block_size);
	chunks_sig = fu_chunk_array_new_from_bytes (signature_bin,
						    0x00,	/* start addr */
						    0x00,	/* page_sz */
						    flash->block_size);
	chunks_cfg = fu_chunk_array_new_from_bytes (bytes_cfg,
						    0x00,	/* start addr */
						    0x00,	/* page_sz */
						    flash->block_size);
	for (guint i = 0; i < chunks_bin->len; i++) {
		FuChunk *chk = g_ptr_array_index (chunks_bin, i);
		if (!fu_synaptics_rmi_v5_device_write_block (self,
							     RMI_V5_FLASH_CMD_WRITE_FW_BLOCK,
							     address,
							     chk->data,
							     chk->data_sz,
							     error)) {
			g_prefix_error (error, "failed to write bin block %u: ", chk->idx);
			return FALSE;
		}
		fu_device_set_progress_full (device, (gsize) i,
					     (gsize) chunks_bin->len + chunks_cfg->len);
	}
	if (fu_synaptics_rmi_firmware_get_signature_size (rmi_firmware) != 0 &&
	    fu_synaptics_rmi_device_get_rsa_keylen (self) != 0) {
		g_debug ("need write signature");
		if (!fu_synaptics_rmi_device_write (self, f34->data_base, req_addr, error)) {
			g_prefix_error (error, "failed to write 1st address zero: ");
			return FALSE;
		}
		for (guint i = 0; i < chunks_sig->len; i++) {
			FuChunk *chk = g_ptr_array_index (chunks_sig, i);
			if (!fu_synaptics_rmi_v5_device_write_block (self,
							     RMI_V5_FLASH_CMD_WRITE_SIGNATURE,
							     address,
							     chk->data,
							     chk->data_sz,
							     error)) {
				g_prefix_error (error, "failed to write bin block %u: ", chk->idx);
				return FALSE;
			}
			fu_device_set_progress_full (device, (gsize) i,
					     (gsize) chunks_bin->len + chunks_cfg->len);
		}
		g_usleep (1000 * 1000);
	}

	if (!fu_synaptics_rmi_device_enter_backdoor (self, error)) {
		g_prefix_error (error, "failed to enable backdoor: ");
		return FALSE;
	}

	/* program the configuration image */
	if (!fu_synaptics_rmi_device_write (self, f34->data_base, req_addr, error)) {
		g_prefix_error (error, "failed to 2nd write address zero: ");
		return FALSE;
	}
	for (guint i = 0; i < chunks_cfg->len; i++) {
		FuChunk *chk = g_ptr_array_index (chunks_cfg, i);
		if (!fu_synaptics_rmi_v5_device_write_block (self,
							     RMI_V5_FLASH_CMD_WRITE_CONFIG_BLOCK,
							     address,
							     chk->data,
							     chk->data_sz,
							     error)) {
			g_prefix_error (error, "failed to write cfg block %u: ", chk->idx);
			return FALSE;
		}
		fu_device_set_progress_full (device,
					     (gsize) chunks_bin->len + i,
					     (gsize) chunks_bin->len + chunks_cfg->len);
	}

	g_usleep (2000 * 1000);
	/* success */
	return TRUE;
}

gboolean
fu_synaptics_rmi_v5_device_setup (FuSynapticsRmiDevice *self, GError **error)
{
	FuSynapticsRmiFunction *f34;
	FuSynapticsRmiFlash *flash = fu_synaptics_rmi_device_get_flash (self);
	guint8 flash_properties2 = 0;
	g_autoptr(GByteArray) f34_data0 = NULL;
	g_autoptr(GByteArray) f34_data2 = NULL;
	g_autoptr(GByteArray) buf_flash_properties2 = NULL;

	/* f34 */
	f34 = fu_synaptics_rmi_device_get_function (self, 0x34, error);
	if (f34 == NULL)
		return FALSE;

	/* get bootloader ID */
	f34_data0 = fu_synaptics_rmi_device_read (self, f34->query_base, 0x2, error);
	if (f34_data0 == NULL) {
		g_prefix_error (error, "failed to read bootloader ID: ");
		return FALSE;
	}
	flash->bootloader_id[0] = f34_data0->data[0];
	flash->bootloader_id[1] = f34_data0->data[1];

	buf_flash_properties2 = fu_synaptics_rmi_device_read (self, f34->query_base + 0x9, 1, error);
	if (buf_flash_properties2 == NULL) {
		g_prefix_error (error, "failed to read Flash Properties 2: ");
		return FALSE;
	}
	if (!fu_common_read_uint8_safe (buf_flash_properties2->data,
					buf_flash_properties2->len,
					0x0, /* offset */
					&flash_properties2,
					error)) {
		g_prefix_error (error, "failed to parse Flash Properties 2: ");
		return FALSE;
	}
	if (flash_properties2 & 0x01) {
		guint16 rsa_keylen = 0;
		g_autoptr(GByteArray) buf_rsa_key = NULL;
		buf_rsa_key = fu_synaptics_rmi_device_read (self,
							    f34->query_base + 0x9 + 0x1,
							    2,
							    error);
		if (buf_rsa_key == NULL) {
			g_prefix_error (error, "failed to read RSA key length: ");
			return FALSE;
		}
		if (!fu_common_read_uint16_safe (buf_rsa_key->data,
						 buf_rsa_key->len,
						 0x0, /* offset */
						 &rsa_keylen,
						 G_LITTLE_ENDIAN,
						 error)) {
			g_prefix_error (error, "failed to parse RSA key length: ");
			return FALSE;
		}
		g_debug ("RSA key length: %d", rsa_keylen);
		fu_synaptics_rmi_device_set_rsa_keylen (self, rsa_keylen);
	} else {
		fu_synaptics_rmi_device_set_rsa_keylen (self, 0);
	}

	/* get flash properties */
	f34_data2 = fu_synaptics_rmi_device_read (self, f34->query_base + 0x2, 0x7, error);
	if (f34_data2 == NULL)
		return FALSE;
	flash->block_size = fu_common_read_uint16 (f34_data2->data + RMI_F34_BLOCK_SIZE_OFFSET, G_LITTLE_ENDIAN);
	flash->block_count_fw = fu_common_read_uint16 (f34_data2->data + RMI_F34_FW_BLOCKS_OFFSET, G_LITTLE_ENDIAN);
	flash->block_count_cfg = fu_common_read_uint16 (f34_data2->data + RMI_F34_CONFIG_BLOCKS_OFFSET, G_LITTLE_ENDIAN);
	flash->status_addr = f34->data_base + RMI_F34_BLOCK_DATA_OFFSET + flash->block_size;
	return TRUE;
}

gboolean
fu_synaptics_rmi_v5_device_query_status (FuSynapticsRmiDevice *self, GError **error)
{
	FuSynapticsRmiFunction *f01;
	g_autoptr(GByteArray) f01_db = NULL;

	/* f01 */
	f01 = fu_synaptics_rmi_device_get_function (self, 0x01, error);
	if (f01 == NULL)
		return FALSE;
	f01_db = fu_synaptics_rmi_device_read (self, f01->data_base, 0x1, error);
	if (f01_db == NULL) {
		g_prefix_error (error, "failed to read the f01 data base: ");
		return FALSE;
	}
	if (f01_db->data[0] & 0x40) {
		fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
	} else {
		fu_device_remove_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_IS_BOOTLOADER);
	}
	return TRUE;
}
