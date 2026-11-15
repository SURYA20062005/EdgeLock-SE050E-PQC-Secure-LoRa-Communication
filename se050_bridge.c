#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include "ex_sss_boot.h"
#include "fsl_sss_se05x_apis.h"
#include "se05x_APDU.h"
#include "nxLog_App.h"
#define EX_SSS_BOOT_PCONTEXT (&g_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0
static ex_sss_boot_ctx_t g_boot_ctx;
#define OWN_PUB_ID 0x7A050A28u
#define OWN_PRIV_ID 0x7A050A29u
#define PEER_ID 0x7A050A31u
#define AES_ID 0x7A05F041u /* dedicated SCP03 session object; existing 0x7A050A30 untouched */
#define MAX_DATA 8192
static char cmd[24];
static uint8_t in[MAX_DATA];
static size_t in_len;
static int get_input(void) {
  uint8_t n[4];
  if (scanf("%23s",cmd)!=1) return 0;
  if (getchar()!='\n') return 0;
  if (fread(n,1,4,stdin)!=4) return 0;
  in_len=((size_t)n[0]<<24)|((size_t)n[1]<<16)|((size_t)n[2]<<8)|n[3];
  return in_len<=MAX_DATA && fread(in,1,in_len,stdin)==in_len;
}
static void emit(const uint8_t *p,size_t n){ printf("RESULT:"); for(size_t i=0;i<n;i++) printf("%02x",p[i]); printf("\n"); fflush(stdout); }
static sss_status_t lookup(sss_se05x_key_store_t *ks,sss_se05x_object_t *obj,uint32_t id){
  sss_status_t s=sss_se05x_key_object_init(obj,ks);
  if(s!=kStatus_SSS_Success) return s;
  return sss_se05x_key_object_get_handle(obj,id);
}
/* Object inventory is read-only; distinguish absent IDs from lookup errors. */
static int object_exists(sss_se05x_session_t *session,uint32_t target){
  uint16_t offset=0; uint8_t more=kSE05x_MoreIndicator_NA;
  do{
    uint8_t ids[1024]={0}; size_t n=sizeof(ids);
    smStatus_t r=Se05x_API_ReadIDList(&session->s_ctx,offset,0xFF,&more,ids,&n);
    if(r!=SM_OK || n>sizeof(ids) || n%4 || (more==kSE05x_MoreIndicator_MORE && !n)) return -1;
    for(size_t i=0;i<n;i+=4){
      uint32_t id=((uint32_t)ids[i]<<24)|((uint32_t)ids[i+1]<<16)|((uint32_t)ids[i+2]<<8)|ids[i+3];
      if(id==target) return 1;
    }
    if(offset+n>65535) return -1;
    offset+=(uint16_t)n;
  }while(more==kSE05x_MoreIndicator_MORE);
  return 0;
}
/* Create persistent objects with secure messaging required. Never replace identity or peer keys. */
static sss_status_t create_protected(sss_se05x_key_store_t *ks,uint32_t id,sss_cipher_type_t cipher,const uint8_t *data,size_t len){
  sss_se05x_object_t obj={0}; sss_status_t s=sss_se05x_key_object_init(&obj,ks);
  if(s!=kStatus_SSS_Success) return s;
  s=sss_se05x_key_object_allocate_handle(&obj,id,kSSS_KeyPart_Default,cipher,len,kKeyObject_Mode_Persistent);
  if(s!=kStatus_SSS_Success) goto done;
  sss_policy_u common={0},sym={0}; sss_policy_t policies={0};
  common.type=KPolicy_Common; common.auth_obj_id=0;
  common.policy.common.can_Read=1;
  common.policy.common.can_Write=1;
  common.policy.common.can_Delete=1;
  common.policy.common.req_Sm=1;
  policies.policies[0]=&common; policies.nPolicies=1;
  if(cipher==kSSS_CipherType_AES){
    sym.type=KPolicy_Sym_Key; sym.auth_obj_id=0;
    sym.policy.symmkey.can_Encrypt=1;
    sym.policy.symmkey.can_Decrypt=1;
    policies.policies[1]=&sym; policies.nPolicies=2;
  }
  s=sss_se05x_key_store_set_key(ks,&obj,data,len,len*8,&policies,sizeof(policies));
done: sss_se05x_key_object_free(&obj); return s;
}
/* Only the dedicated session-key ID may be erased for rekeying. */
static sss_status_t replace_session_aes(sss_se05x_key_store_t *ks,sss_se05x_session_t *session,const uint8_t *key){
  int exists=object_exists(session,AES_ID);
  if(exists<0) return kStatus_SSS_Fail;
  sss_se05x_object_t obj={0};
  sss_status_t s=kStatus_SSS_Success;
  if(exists){
    s=lookup(ks,&obj,AES_ID);
    if(s!=kStatus_SSS_Success){sss_se05x_key_object_free(&obj);return s;}
    s=sss_se05x_key_store_erase_key(ks,&obj);
    sss_se05x_key_object_free(&obj);
    if(s!=kStatus_SSS_Success) return s;
  }
  return create_protected(ks,AES_ID,kSSS_CipherType_AES,key,32);
}
sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *ctx){
  sss_se05x_key_store_t *ks=(sss_se05x_key_store_t *)&ctx->ks;
  sss_se05x_session_t *session=(sss_se05x_session_t *)&ctx->session;
  sss_status_t s=kStatus_SSS_Fail;
  if(!strcmp(cmd,"own-write")){
    /* Input: 1952-byte public key followed by 4032-byte private key.
       Only provisioning calls this command. Existing identities are NOT overwritten. */
    if(in_len!=5984) return s;
    if(object_exists(session,OWN_PUB_ID)!=0 || object_exists(session,OWN_PRIV_ID)!=0){
      fprintf(stderr,"Identity already exists or inventory unavailable: refusing write\n");
      return kStatus_SSS_Fail;
    }
    s=create_protected(ks,OWN_PUB_ID,kSSS_CipherType_Binary,in,1952);
    if(s!=kStatus_SSS_Success) return s;
    return create_protected(ks,OWN_PRIV_ID,kSSS_CipherType_Binary,in+1952,4032);
  }
  /* Explicit per-run identity rekey: erase ONLY the two dedicated identity IDs.
     Not atomic: interrupted provisioning requires a fresh run. */
  if(!strcmp(cmd,"own-replace")){
    if(in_len!=5984) return s;
    const uint32_t ids[2]={OWN_PUB_ID,OWN_PRIV_ID};
    for(size_t i=0;i<2;i++){
      int present=object_exists(session,ids[i]);
      if(present<0) return kStatus_SSS_Fail;
      if(present){
        sss_se05x_object_t old={0};
        s=lookup(ks,&old,ids[i]);
        if(s!=kStatus_SSS_Success){sss_se05x_key_object_free(&old);return s;}
        s=sss_se05x_key_store_erase_key(ks,&old);
        sss_se05x_key_object_free(&old);
        if(s!=kStatus_SSS_Success) return s;
      }
    }
    s=create_protected(ks,OWN_PUB_ID,kSSS_CipherType_Binary,in,1952);
    if(s!=kStatus_SSS_Success) return s;
    return create_protected(ks,OWN_PRIV_ID,kSSS_CipherType_Binary,in+1952,4032);
  }
  /* Replace only the dedicated trusted peer public-key object. */
  if(!strcmp(cmd,"peer-replace")){
    if(in_len!=1952) return s;
    int present=object_exists(session,PEER_ID);
    if(present<0) return kStatus_SSS_Fail;
    if(present){
      sss_se05x_object_t old={0};
      s=lookup(ks,&old,PEER_ID);
      if(s!=kStatus_SSS_Success){sss_se05x_key_object_free(&old);return s;}
      s=sss_se05x_key_store_erase_key(ks,&old);
      sss_se05x_key_object_free(&old);
      if(s!=kStatus_SSS_Success) return s;
    }
    return create_protected(ks,PEER_ID,kSSS_CipherType_Binary,in,in_len);
  }
  if(!strcmp(cmd,"own-reset") || !strcmp(cmd,"all-reset")){
    fprintf(stderr,"Identity reset commands DISABLED in SCP03 project\n");
    return kStatus_SSS_Fail;
  }
  if(!strcmp(cmd,"peer-write")){
    if(in_len!=1952) return s;
    /* Existing peer key must not be silently overwritten. */
    if(object_exists(session,PEER_ID)!=0) return kStatus_SSS_Fail;
    return create_protected(ks,PEER_ID,kSSS_CipherType_Binary,in,in_len);
  }
  if(!strcmp(cmd,"aes-import")){
    if(in_len!=32) return s;
    return replace_session_aes(ks,session,in);
  }
  sss_se05x_object_t obj={0};
  if(!strcmp(cmd,"own-public") || !strcmp(cmd,"own-secret")){
    int priv=!strcmp(cmd,"own-secret");
    uint8_t out[4032]; size_t n=priv?4032:1952,bits=0;
    s=lookup(ks,&obj,priv?OWN_PRIV_ID:OWN_PUB_ID); if(s!=kStatus_SSS_Success) goto end;
    s=sss_se05x_key_store_get_key(ks,&obj,out,&n,&bits);
    if(s==kStatus_SSS_Success && n==(priv?4032u:1952u)) emit(out,n);
    else s=kStatus_SSS_Fail;
    OPENSSL_cleanse(out,sizeof(out)); goto end;
  }
  if(!strcmp(cmd,"peer-read")){
    uint8_t out[1952]; size_t n=sizeof(out),bits=0;
    s=lookup(ks,&obj,PEER_ID); if(s!=kStatus_SSS_Success) goto end;
    s=sss_se05x_key_store_get_key(ks,&obj,out,&n,&bits);
    if(s==kStatus_SSS_Success && n==1952) emit(out,n); else s=kStatus_SSS_Fail;
    OPENSSL_cleanse(out,sizeof(out)); goto end;
  }
  if(strcmp(cmd,"encrypt") && strcmp(cmd,"decrypt")) goto end;
  /* Frame: nonce(12) | aad_len(2) | data_len(2) | tag(16 for decrypt) | aad | data */
  if(in_len<16) goto end;
  uint8_t *nonce=in;
  size_t al=((size_t)in[12]<<8)|in[13], dl=((size_t)in[14]<<8)|in[15];
  int decrypt=!strcmp(cmd,"decrypt");
  size_t pos=16+(decrypt?16:0);
  if(dl>4096 || al>512 || pos+al+dl!=in_len) goto end;
  uint8_t *tag=decrypt?in+16:NULL;
  uint8_t *aad=in+pos,*data=aad+al;
  uint8_t *out=calloc(dl+16,1); if(!out) goto end;
  uint8_t tagbuf[16]={0}; size_t taglen=16;
  if(decrypt) memcpy(tagbuf,tag,16);
  s=lookup(ks,&obj,AES_ID); if(s!=kStatus_SSS_Success) goto done;
  sss_se05x_aead_t aead={0};
  s=sss_se05x_aead_context_init(&aead,session,&obj,kAlgorithm_SSS_AES_GCM,decrypt?kMode_SSS_Decrypt:kMode_SSS_Encrypt);
  if(s!=kStatus_SSS_Success) goto done;
  s=sss_se05x_aead_one_go(&aead,data,out,dl,nonce,12,aad,al,tagbuf,&taglen);
  sss_se05x_aead_context_free(&aead);
  if(s==kStatus_SSS_Success && taglen==16){
    if(decrypt) emit(out,dl);
    else { uint8_t *combined=malloc(dl+16); if(!combined){s=kStatus_SSS_Fail;}else{memcpy(combined,out,dl);memcpy(combined+dl,tagbuf,16);emit(combined,dl+16);OPENSSL_cleanse(combined,dl+16);free(combined);} }
  } else s=kStatus_SSS_Fail;
done: OPENSSL_cleanse(out,dl+16);free(out);
end: sss_se05x_key_object_free(&obj);return s;
}
#define main nxp_main
#include <ex_sss_main_inc.h>
#undef main
int main(int argc,const char *argv[]){
 if(!get_input()){fprintf(stderr,"Invalid command/input\n");return 2;}
 int rc=nxp_main(argc,argv);OPENSSL_cleanse(in,sizeof(in));return rc;
}
