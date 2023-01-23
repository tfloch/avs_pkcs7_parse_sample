#include <zephyr.h>
#include <sys/printk.h>
#include <drivers/uart.h>
#include <drivers/gpio.h>
#include <net/net_mgmt.h>
#include <net/socket.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/oid.h>

#include <avsystem/commons/avs_log.h>
#include <avsystem/commons/avs_net.h>
#include <avsystem/commons/avs_prng.h>
#include <avsystem/commons/avs_sched.h>
#include <avsystem/commons/avs_utils.h>

/// @brief Certificate information string size
#define UI32_SIZE_CERT_INFO             2000

static const unsigned char pkcs7_good[] = {
   #include "good.pkcs7.der.inc"
};

static const unsigned char pkcs7_bad[] = {
   #include "bad.pkcs7.der.inc"
};


void parse_pkcs7_anjay(const unsigned char *cpc_Pkcs7Der, size_t z_Pkcs7DerLen)
{
   // For mbedtls
   int i_Ret;
   mbedtls_x509_crt k_MbedCerts;
   mbedtls_x509_crt *pk_MbedCurrentCert = &k_MbedCerts;

   // For Anjay
   AVS_LIST(avs_crypto_certificate_chain_info_t) pk_AvsCertList = NULL;
   AVS_LIST(avs_crypto_cert_revocation_list_info_t) pk_AvsCrlList = NULL;
   avs_crypto_certificate_chain_info_t *pk_AvsCert = NULL;
   avs_error_t k_AvsErr;

   // To print certificates
   char ac_CertInfo[UI32_SIZE_CERT_INFO] = { 0 };

   // Extract CRL and Certs from PKCS7 payload, using anjay
   k_AvsErr = avs_crypto_parse_pkcs7_certs_only(&pk_AvsCertList, &pk_AvsCrlList, cpc_Pkcs7Der, z_Pkcs7DerLen);

   if (avs_is_err(k_AvsErr))
   {
      printf("avs_crypto_parse_pkcs7_certs_only error\n");
      return;
   }

   mbedtls_x509_crt_init(&k_MbedCerts);

   // For each certificate in AVS_LIST
   AVS_LIST_FOREACH(pk_AvsCert, pk_AvsCertList)
   {
      // Add certificate to k_MbedCerts chained list
      i_Ret = mbedtls_x509_crt_parse(
         &k_MbedCerts,
         (const unsigned char *) pk_AvsCert->desc.info.buffer.buffer,
         pk_AvsCert->desc.info.buffer.buffer_size);

      if (i_Ret < 0)
      {
         printf("mbedtls_x509_crt_parse error %d\n", i_Ret);
         return;
      }
   }

   while (pk_MbedCurrentCert != NULL)
   {
      i_Ret = mbedtls_x509_crt_info( (char *) ac_CertInfo, sizeof(ac_CertInfo), "", pk_MbedCurrentCert);

      if (i_Ret < 0)
      {
         printf("mbedtls_x509_crt_info error %d\n", i_Ret);
         return;
      }

      printf("\n%s\n", ac_CertInfo);

      // Next certificate
      pk_MbedCurrentCert = pk_MbedCurrentCert->next;
   }

   // Free mbedtls_x509_crt* in chained list
   mbedtls_x509_crt_free(&k_MbedCerts);
   return;
}

void main(void)
{
   printf("\nDecode good.pkcs7.der using anjay\n");
   parse_pkcs7_anjay(pkcs7_good, sizeof(pkcs7_good));

   printf("\nDecode bad.pkcs7.der using anjay\n");
   parse_pkcs7_anjay(pkcs7_bad, sizeof(pkcs7_bad));
}

