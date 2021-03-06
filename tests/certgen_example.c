/*---------------------------------------------------------------------------*/ 
/* Generating and verifying a chain of Trust based on XMSS signatures        */
/* Author SOundes Marzougui                                                  */
/* Technische Universität Berlin                                             */
/*---------------------------------------------------------------------------*/

#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>


#include <wolfssl/wolfcrypt/params.h>
#include <wolfssl/wolfcrypt/randombytes.h>
#include <wolfssl/wolfcrypt/xmss.h>

#define HAVE_XMSS 

#define HEAP_HINT NULL
#define FOURK_SZ 4096  
#define XMSS_MLEN 32

   
#define XMSS_PARSE_OID xmss_parse_oid
#define XMSS_STR_TO_OID xmss_str_to_oid
#define XMSS_KEYPAIR xmss_keypair
#define XMSS_SIGN xmss_sign
#define XMSS_SIGN_OPEN xmss_sign_open
#define XMSS_VARIANT "XMSS-SHA2_10_256"
 


#if defined(WOLFSSL_CERT_REQ) && defined(WOLFSSL_CERT_GEN)
void free_things(byte** a, byte** b, byte** c, ecc_key* d, ecc_key* e,
                 WC_RNG* f);
#endif

int main(void) {
#if !defined(WOLFSSL_CERT_REQ) || !defined(WOLFSSL_CERT_GEN)
  printf("Please compile wolfSSL with --enable-certreq --enable-certgen\n");
  return 0;
#else


    Cert newCert;
    FILE* file; 
    char newCertOutput[] = "./newCert.der";
    char certToUse[] = "./ca-ecc-cert.der";
    int derBufSz; 

    byte* derBuf   = NULL;
    byte* pemBuf   = NULL;
    byte* caKeyBuf = NULL;
    
    /* for MakeCert and SignCert */
    WC_RNG rng;
    ecc_key caKey;
    ecc_key newKey;  
    int ret = 0;
    int kid_type = 0;
/*----------------------------------------------------------------------------------------*/ 
/* Create XMSS Key pairs                                                                  */
/* These n-key pairs are used for the n-entities of our chain of trust(CA excluded)       */
/*----------------------------------------------------------------------------------------*/
    xmss_params params;
    uint32_t oid;   
    XMSS_STR_TO_OID(&oid, XMSS_VARIANT); // e.g. XMSS-SHA2_10_256
    XMSS_PARSE_OID(&params, oid);

   
    unsigned char pk[XMSS_OID_LEN + params.pk_bytes]; 
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];   
    XMSS_KEYPAIR(pk, sk, oid);

    printf("Successfully create XMSS Keys\n");
    printf("Size of public key is: %d\n", XMSS_OID_LEN + params.pk_bytes);
    printf("Size of secret key is: %d\n", XMSS_OID_LEN + params.sk_bytes); 



/*----------------------------------------------------------------------------*/
/* open the CA der formatted certificate, we need to get it's subject line to */
/* use in the new cert we're creating as the "Issuer" line                    */
/*----------------------------------------------------------------------------*/
    
//The CA in our case should be a self-signed DILITHIUM cert. Initially, we 
//adopt an ecc cert, TODO should be changed to DILITHIUM cert 
    long long int FOURK_SZZ = 10000; 
    printf("FourkZ %d", FOURK_SZZ);
    derBuf = malloc(FOURK_SZZ);
    XMEMSET(derBuf, 0, FOURK_SZZ); 
/*---------------------------------------------------------------------------*/
/* END */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* initializing the rng */
/*---------------------------------------------------------------------------*/
    printf("initializing the rng\n");
    ret = wc_InitRng(&rng); 
/*---------------------------------------------------------------------------*/
/* END */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Create a new certificate using SUBJECT information from ca cert
 * for ISSUER information in generated cert */
/*---------------------------------------------------------------------------*/
    printf("Setting new cert issuer to subject of signer\n");

    wc_InitCert(&newCert);
    //Set subject 
    strncpy(newCert.subject.country, "DE", CTC_NAME_SIZE);
    strncpy(newCert.subject.state, "Germany", CTC_NAME_SIZE);
    strncpy(newCert.subject.locality, "Berlin", CTC_NAME_SIZE);
    strncpy(newCert.subject.org, "TU Berlin", CTC_NAME_SIZE);
    strncpy(newCert.subject.unit, "SecT", CTC_NAME_SIZE);
    strncpy(newCert.subject.commonName, "www.TuBerlin.com", CTC_NAME_SIZE);
    strncpy(newCert.subject.email, "soundes.marzougui@tu-berlin.com", CTC_NAME_SIZE);

    //Set issuer
    strncpy(newCert.issuer.country, "US", CTC_NAME_SIZE);
    strncpy(newCert.issuer.state, "Washington", CTC_NAME_SIZE);
    strncpy(newCert.issuer.locality, "Boston", CTC_NAME_SIZE);
    strncpy(newCert.issuer.org, "Crypto", CTC_NAME_SIZE);
    strncpy(newCert.issuer.unit, "Wolfssl", CTC_NAME_SIZE);
    strncpy(newCert.issuer.commonName, "www.WolfSSl.com", CTC_NAME_SIZE);
    strncpy(newCert.issuer.email, "Wolfssl@wolfssl.com", CTC_NAME_SIZE);

    //Others
    newCert.isCA    = 1;
    newCert.selfSigned = 1;
    newCert.sigType = CTC_XMSS;



    ret = wc_SetSubjectKeyIdFromXMSSPublicKey(&newCert, pk, kid_type);//set the XMSS key as a subject public key 
    if (ret < 0) goto fail;
 
    ret = wc_MakeXMSSCert(&newCert, derBuf, FOURK_SZ,(byte*) pk, XMSS_OID_LEN + params.pk_bytes, &rng); //xmss certificate
    //ret = wc_MakeCert(&newCert, derBuf, FOURK_SZ, NULL, &newKey, &rng); //ecc certificate
 
    if (ret < 0) goto fail;
  
    printf("Make XMSS Cert returned %d\n", ret);

    ret = wc_SignXMSSCert(newCert.bodySz, newCert.sigType, derBuf, FOURK_SZ, sk);// sign the certificate with the secret key, well yes it is a self signed certificate but this should be changed 
    if (ret < 0) goto fail;
    printf("Sign XMSS Cert returned %d\n", ret);

    derBufSz = ret; 


    printf("Successfully created new certificate\n");
/*---------------------------------------------------------------------------*/
/* END */
/*---------------------------------------------------------------------------*/
 
 

/*---------------------------------------------------------------------------*/
/* Verifying the XMSS signature                                              */
/*---------------------------------------------------------------------------*/

 
    byte * smex = malloc(params.sig_bytes + XMSS_MLEN);// size of signature
    for(int i=0;i<sigSz;i++){
       smex[i] = buf[derBuf+derBufSz];//540+seqSz the returned value of AddSignature
       //printf("smex is %c buf is %c \n", smex[i], buf[i]);

    }
      
    //verification of signature
    xmss_sign_open(mout, &mlen, sm, smlen, pk);
    printf("+++++++++++++++++++++\n");
    if(*mout == *buf) printf(" Correct signature !\n");
    else  printf(" Wrong signature !\n");
    printf("+++++++++++++++++++++\n"); 
    //end verification 

/*---------------------------------------------------------------------------*/
/* END */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Print XMSS certificate                                                    */
/*---------------------------------------------------------------------------*/
printf("**********************Certificate begin********************** \n" );
printf("Certificate version: X509 v.%d \n", newCert.version);
printf("Issuer: country %s, state: %s, locality: %s\n", newCert.issuer.country, newCert.issuer.state, newCert.issuer.locality);
printf("Subject: country %s, state: %s, locality: %s\n", newCert.subject.country, newCert.subject.state, newCert.subject.locality);
if(newCert.isCA == 0)
	printf("Certificate CA: No\n" );
else
printf("Certificate CA: Yes\n" );
if(newCert.selfSigned == 0)
	printf("Self signed ertificate: No\n" );
else
printf("Self signed ertificate: Yes\n" );

printf("Validity days: %d\n",  newCert.daysValid ); 

printf("**********************Certificate end************************ \n" );
/*---------------------------------------------------------------------------*/
/* END                                                                       */
/*---------------------------------------------------------------------------*/
 

/*---------------------------------------------------------------------------*/
/* write the new cert to file in der format */
/*---------------------------------------------------------------------------*/
    printf("Writing newly generated certificate to file \"%s\"\n",
                                                                 newCertOutput); 
    file = fopen(newCertOutput, "wb");
    if (!file) {
        printf("failed to open file: %s\n", newCertOutput);
        goto fail;
    }

    ret = (int) fwrite(derBuf, 1, derBufSz, file);
    fclose(file);
    printf("Successfully output %d bytes\n", ret);
/*---------------------------------------------------------------------------*/
/* END */
/*---------------------------------------------------------------------------*/


    goto success;

fail:
    //free_things(&derBuf, &pemBuf, &caKeyBuf, &caKey, &newKey, &rng);
    printf("Failure code was %d\n", ret);
    return -1;

success:
    //free_things(&derBuf, &pemBuf, &caKeyBuf, &caKey, &newKey, &rng);
    printf("Tests passed\n");
    return 0;
}

void free_things(byte** a, byte** b, byte** c, ecc_key* d, ecc_key* e,
                                                                      WC_RNG* f)
{
    if (a != NULL) {
        if (*a != NULL) {
            XFREE(*a, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            *a = NULL;
        }
    }
    if (b != NULL) {
        if (*b != NULL) {
            XFREE(*b, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            *b = NULL;
        }
    }
    if (c != NULL) {
        if (*c != NULL) {
            XFREE(*c, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            *c = NULL;
        }
    }

    wc_ecc_free(d);
    wc_ecc_free(e);
    wc_FreeRng(f);
#endif
}


