#!/usr/bin/env python3
"""
FEAL differential cryptanalysis (chosen-plaintext).

USAGE
    When a FEAL encryption oracle (hex in, hex out) reduced to a few rounds is
    available and the key must be recovered. Works for R = 4..6; R = 7 is marginal
    and R = 8 needs more pairs than a typical per-connection query limit allows.

HOW IT WORKS
    FEAL's round function has a probability-1 differential (input 0x80800000 ->
    output 0x02000000). From it a sparse multi-round characteristic is built. For
    each round from the last inward, the correct last-round subkey satisfies
    f(C_low, K) ^ f(C_low', K) == C_high_diff ^ predicted_dR over the chosen pairs
    (counting when the prediction is probabilistic, set-intersection when it is
    deterministic); the round is then peeled. The remaining bottom rounds, whose f
    input difference is 0 or magic (blind), are finished with two short
    characteristics and a whitening-consistency step.

RUN
    Enter host/port. Gathers pairs, tries several round counts, keeps the one whose
    key re-encrypts a known pair, then decrypts the banner flag. Requires numpy.

NOTES
    - The round count is a parameter, not an assumption: it tries a list (R_TRY).
    - Oracles often cap queries per connection and may regenerate the key each
      connection, so all pairs and the flag must come from one connection; queries
      are sent in small chunks with a read after each to avoid a reset.
    - The flag may be packed little-endian per 8-byte block, so both byte orders are
      printed; the readable one is the flag.
    - Data cost scales as ~1/characteristic_probability. The built-in 6-round
      characteristic is ~2^-14 with a deterministic 3-round prefix; ~2000 pairs
      suffice up to R = 6.

CIPHER MODEL
    cipher = plain ^ W                 # 64-bit input whitening, no output whitening
    for i in 0..R-1: tmp = L ^ f(R, Ki); L = R; R = tmp
    cipher = R<<32 | L                 # final swap
    with a 16-bit-subkey round function f (key bytes XORed into the two middle bytes).
"""

import numpy as np, socket, re, time, sys

MASK = 0xFFFFFFFF; M64 = (1 << 64) - 1; U32 = np.uint32; U64 = np.uint64
rotl2 = lambda v: ((v << 2) | (v >> 6)) & 0xff

# --- scalar f / encrypt / decrypt (for the final verify and the flag) ---
def fs(R, K):
    a0=(R>>24)&0xff;a1=(R>>16)&0xff;a2=(R>>8)&0xff;a3=R&0xff;b0=(K>>8)&0xff;b1=K&0xff
    g=lambda v:(((v&0xff)<<2)|((v&0xff)>>6))&0xff
    f1=g((a1^b0^a0)+(a2^b1^a3)+1); f2=g((a2^b1^a3)+f1)
    f0=g(a0+f1); f3=g(a3+f2+1)
    return (f0<<24)|(f1<<16)|(f2<<8)|f3
def enc_blk(P,K,W,R):
    X=int(P)^W;L=(X>>32)&MASK;Rr=X&MASK
    for i in range(R): t=L^fs(Rr,K[i]);L=Rr;Rr=t&MASK
    return (Rr<<32)|L
def dec_blk(C,K,W,R):
    L=C&MASK;Rr=C>>32
    for i in range(R-1,-1,-1): Y=fs(L,K[i]);nR=L;nL=(Rr^Y)&MASK;L=nL;Rr=nR
    return (((L<<32)|Rr)^W)&M64

# --- vectorized f (numpy) for fast peeling and counting ---
def f_sk(R,K):
    b0=(K>>8)&0xff;b1=K&0xff
    a0=((R>>24)&0xff).astype(np.uint16);a1=((R>>16)&0xff).astype(np.uint16)
    a2=((R>>8)&0xff).astype(np.uint16);a3=(R&0xff).astype(np.uint16)
    f1=rotl2(((a1^b0^a0)+(a2^b1^a3)+1)&0xff); f2=rotl2((((a2^b1^a3))+f1)&0xff)
    f0=rotl2((a0+f1)&0xff); f3=rotl2((a3+f2+1)&0xff)
    return (f0.astype(U32)<<24)|(f1.astype(U32)<<16)|(f2.astype(U32)<<8)|f3.astype(U32)
def peel(Carr,K):
    CL=(Carr>>U64(32)).astype(U32);CR=(Carr&U64(0xffffffff)).astype(U32)
    return (CR.astype(U64)<<U64(32))|((CL^f_sk(CR,K)).astype(U64))
KB0=(np.arange(65536,dtype=np.uint16)>>8); KB1=(np.arange(65536,dtype=np.uint16)&0xff)
def f_allK(x):                        # f(x, every 16-bit key) -> array[65536]
    a0=(x>>24)&0xff;a1=(x>>16)&0xff;a2=(x>>8)&0xff;a3=x&0xff
    f1=rotl2(((a1^KB0^a0).astype(np.uint16)+(a2^KB1^a3).astype(np.uint16)+1)&0xff)
    f2=rotl2(((a2^KB1^a3).astype(np.uint16)+f1)&0xff);f0=rotl2((a0+f1)&0xff);f3=rotl2((a3+f2+1)&0xff)
    return (f0.astype(U32)<<24)|(f1.astype(U32)<<16)|(f2.astype(U32)<<8)|f3.astype(U32)
def f_mat(xs):                        # f(each x, each key) -> array[len(xs),65536]
    a0=((xs>>24)&0xff).astype(np.uint16)[:,None];a1=((xs>>16)&0xff).astype(np.uint16)[:,None]
    a2=((xs>>8)&0xff).astype(np.uint16)[:,None];a3=(xs&0xff).astype(np.uint16)[:,None]
    f1=rotl2(((a1^KB0[None,:]^a0)+(a2^KB1[None,:]^a3)+1)&0xff)
    f2=rotl2(((a2^KB1[None,:]^a3)+f1)&0xff);f0=rotl2((a0+f1)&0xff);f3=rotl2((a3+f2+1)&0xff)
    return (f0.astype(U32)<<24)|(f1.astype(U32)<<16)|(f2.astype(U32)<<8)|f3.astype(U32)

def count(C0,C1,pred,B=256):          # votes per 16-bit last-round subkey
    CL0=(C0>>U64(32)).astype(U32);CR0=(C0&U64(0xffffffff)).astype(U32)
    CL1=(C1>>U64(32)).astype(U32);CR1=(C1&U64(0xffffffff)).astype(U32)
    tg=CL0^CL1^U32(pred);cnt=np.zeros(65536,dtype=np.int64)
    for s in range(0,len(C0),B):
        cnt+=((f_mat(CR0[s:s+B])^f_mat(CR1[s:s+B]))==tg[s:s+B,None]).sum(axis=0)
    return cnt
def inter(C0,C1,pred,lim=30):         # subkeys satisfying all pairs (deterministic prediction)
    CL0=(C0>>U64(32)).astype(U32);CR0=(C0&U64(0xffffffff)).astype(U32)
    CL1=(C1>>U64(32)).astype(U32);CR1=(C1&U64(0xffffffff)).astype(U32)
    tg=CL0^CL1^U32(pred);cand=None
    for i in range(min(lim,len(C0))):
        d=f_allK(int(CR0[i]))^f_allK(int(CR1[i]));ss=set(np.nonzero(d==tg[i])[0].tolist())
        cand=ss if cand is None else (cand&ss)
        if cand is not None and len(cand)==1:break
    return cand

# built-in 6-round characteristic (from a beam search over the f DDT):
# input difference, and predicted dR_{r-1} used to recover the subkey of round r.
IDIFF=0x0200000080800000; CHAR_A=0x8080000000000000; CHAR_B=0x0200000000000000
DRPRED={7:0x28086080, 6:0xa0008000, 5:0xa8886080, 4:0x02000000, 3:0x80800000}

def attack(R, C0, C1, cA0, cA1, cB0, cB1, P0, Pb0, diag=False):
    def bottom(K):                    # finish K2 (char A), K1 (char B), K0+W (consistency)
        a0,a1=cA0.copy(),cA1.copy()
        for rr in range(R-1,2,-1): a0,a1=peel(a0,K[rr]),peel(a1,K[rr])
        cc=inter(a0,a1,0x80800000)
        if not cc or len(cc)!=1: return None
        K[2]=next(iter(cc))
        b0,b1=cB0.copy(),cB1.copy()
        for rr in range(R-1,1,-1): b0,b1=peel(b0,K[rr]),peel(b1,K[rr])
        cc=inter(b0,b1,0x00000000)
        if not cc or len(cc)!=1: return None
        K[1]=next(iter(cc))
        b0,b1=peel(b0,K[1]),peel(b1,K[1])
        CH=(b0>>U64(32)).astype(U32);CL=(b0&U64(0xffffffff)).astype(U32)
        PL=(Pb0>>U64(32)).astype(U32);PR=(Pb0&U64(0xffffffff)).astype(U32)
        for K0 in range(65536):
            wl=PL^(CH^f_sk(CL,K0)); wr=PR^CL
            if np.all(wl==wl[0]) and np.all(wr==wr[0]):
                K[0]=K0; W=((int(wl[0])<<32)|int(wr[0]))&M64
                if enc_blk(int(P0[0]),K,W,R)==int(C0[0]): return (list(K),W)
        return None
    def rec(r,c0,c1,K):
        if r==2: return bottom(K)
        pred=DRPRED[r]
        if r>=5:                       # probabilistic prediction -> count, try top candidates
            cnt=count(c0,c1,pred); cands=[int(x) for x in np.argsort(-cnt)[:6]]
            if diag: print("  R=%d K%d votes %s"%(R,r,[int(cnt[x]) for x in cands[:4]]),flush=True)
        else:                          # deterministic prediction -> exact intersection
            cc=inter(c0,c1,pred)
            if diag: print("  R=%d K%d intersect cands=%s"%(R,r,len(cc) if cc else 0),flush=True)
            if not cc or len(cc)!=1: return None
            cands=[next(iter(cc))]
        for kc in cands:
            K[r]=kc
            res=rec(r-1,peel(c0,kc),peel(c1,kc),K)
            if res: return res
        return None
    return rec(R-1,C0,C1,[None]*R)


if __name__ == "__main__":
    HOST=input("oracle host: ").strip(); PORT=int(input("oracle port: ").strip())
    NMAIN=int(input("main pairs [2000]: ").strip() or "2000")
    R_TRY=[int(x) for x in (input("rounds to try [6 5 7]: ").strip() or "6 5 7").split()]

    s=socket.socket(); s.connect((HOST,PORT)); s.settimeout(5.0); time.sleep(0.4); bn=b""
    try:
        while True:
            d=s.recv(4096)
            if not d: break
            bn+=d
    except: pass
    m=re.search(rb"([0-9a-fA-F]{32,})",bn); flag_hex=m.group(1).decode() if m else None
    print("banner flag:",flag_hex,flush=True)

    def query(pl,chunk=400):           # small chunks + read-after-send avoids a flood reset
        cts=[]
        for i in range(0,len(pl),chunk):
            part=pl[i:i+chunk]; s.sendall(b"".join(("%016x\n"%p).encode() for p in part))
            out=b""; dl=time.time()+15
            while out.count(b"-> ")<len(part) and time.time()<dl:
                try: dd=s.recv(1<<18)
                except socket.timeout: break
                if not dd: break
                out+=dd
            got=re.findall(rb"-> ([0-9a-f]{16})",out)
            if len(got)!=len(part): raise RuntimeError("short read %d/%d"%(len(got),len(part)))
            cts+=[int(x,16) for x in got]
        return cts

    rng=np.random.default_rng(); mk=lambda d,a:np.array([(int(x)^d)&M64 for x in a],dtype=np.uint64)
    P0=rng.integers(0,1<<64,size=NMAIN,dtype=np.uint64); P1=mk(IDIFF,P0)
    Pa0=rng.integers(0,1<<64,size=20,dtype=np.uint64); Pa1=mk(CHAR_A,Pa0)
    Pb0=rng.integers(0,1<<64,size=20,dtype=np.uint64); Pb1=mk(CHAR_B,Pb0)
    cts=query(list(P0)+list(P1)+list(Pa0)+list(Pa1)+list(Pb0)+list(Pb1)); s.close()
    o=0; take=lambda n: np.array(cts[o:o+n],dtype=np.uint64)
    C0=take(NMAIN); o+=NMAIN; C1=take(NMAIN); o+=NMAIN
    cA0=take(20); o+=20; cA1=take(20); o+=20; cB0=take(20); o+=20; cB1=take(20); o+=20

    sol=None
    for R in R_TRY:
        t0=time.time(); res=attack(R,C0,C1,cA0,cA1,cB0,cB1,P0,Pb0,diag=True)
        print("R=%d -> %s (%.1fs)"%(R,"OK" if res else "no",time.time()-t0),flush=True)
        if res: sol=(R,)+res; break
    if not sol:
        print("[-] no round count worked (raise main pairs, or R too large for the query cap)"); sys.exit(1)
    R,K,W=sol
    print("[+] R=%d  KEY=%s  W=%016x"%(R,[hex(x) for x in K],W))
    if flag_hex:
        fb=bytes.fromhex(flag_hex)
        dec=b"".join(dec_blk(int.from_bytes(fb[i:i+8],'big'),K,W,R).to_bytes(8,'big') for i in range(0,len(fb),8))
        print("[+] flag (big-endian blocks)   :", dec)
        print("[+] flag (little-endian blocks):", b"".join(dec[i:i+8][::-1] for i in range(0,len(dec),8)))
