// SPDX-License-Identifier: CryptoLib.sol
pragma solidity >=0.4.22<0.8.22;
pragma experimental ABIEncoderV2;

import "./EllipticCurve.sol";
import "./EllipticCurveInterface.sol";
import "./SafeMath.sol";
import "./sharedStruct.sol";


contract CryptoLib is EllipticCurveInterface{
    using SafeMath for uint256;
    using sharedStruct for uint256;

    //uint256 public pp = uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F);

    uint256 public H=32864058092162919291441470162988970424366422668150157602553410332660011268801;

    //struct point{
     //   uint256 x;
     //   uint256 y;
    //}

    //struct Enc{
       //  point Cval;
       //  point Rval;
     //    }

    //struct ZKP{
       // point a1;
       // point a2;
       // point a3;
       // uint256 rhat;
       // uint256 rr;
    //    }

    //struct ptxtZKP{
       // point a1;
       // point a2;
       // uint256 rhat;
       // uint256 rr;
     //   }

    modifier isHSet( ){
        require( H == 0);
        _;
    }

    function setH ( ) public
        isHSet
    {
        uint256 TH = uint256( keccak256(abi.encodePacked(block.timestamp,msg.sender)));
        uint256 _p = pp;
        assembly{
            TH := mod(TH,_p)
        }
        H = TH;
    }

    function addmodP( uint256 _v1 , uint256 _v2 )
        internal
        view
        returns( uint256 _v3 )
    {
        uint256 _p = pp;
        assembly{
            _v3 := addmod(_v1,_v2,_p)
        }
    }

    function submodP( uint256 _v1, uint256 _v2 )
        internal
        view
        returns( uint256 _v3 )
    {
        uint256 _p = pp;
        assembly{
            if lt( _v1 , _v2 ){
                _v3 := sub( _p, sub( _v2, _v1 ) )
            }
            if gt(_v1 , _v2) {
                _v3 := mod( sub( _v1, _v2 ), _p )
            }
        }
    }



    function commit( uint256 _r , uint256 _v )
        public
        view
        returns ( uint256 _x3 , uint256 _y3 )
    {
        ( uint256 _lx, uint256 _ly ) = eMul( H, gx, gy);
        ( uint256 _x1, uint256  _y1 ) = eMul( _r, gx, gy);
        ( uint256 _x2, uint256 _y2 ) = eMul( _v, _lx, _ly);
        ( _x3, _y3 ) = eAdd( _x1, _y1, _x2, _y2 );
    }

    function verify( uint256 _r, uint256 _v, uint256 _x1, uint256 _y1 ) public view returns ( bool result )
    {
        (uint256 _x2, uint256 _y2) = commit(_r, _v);
        if ( (_x1 == _x2) && ( _y1 == _y2 ) ){
            result = true;
        }
    }

    function addCommitment( uint256 _r1 ,uint256 _x1 , uint256 _y1 ,  uint256 _r2 , uint256 _x2 , uint256 _y2 )
        public
        view
        returns ( uint256 _r3, uint256 _x3, uint256 _y3 )
    {
        _r3 = addmodP(_r1,_r2);
        ( _x3, _y3 ) = eAdd( _x1, _y1, _x2, _y2 );
    }

    function subCommitment( uint256 _r1 ,uint256 _x1 , uint256 _y1 ,  uint256 _r2 , uint256 _x2 , uint256 _y2 )
        public
        view
        returns ( uint256 _r3, uint256 _x3, uint256 _y3 )
    {
        _r3 = submodP( _r1, _r2 );
        ( _x3, _y3 ) = eSub( _x1, _y1, _x2, _y2 );
    }

    function CiphertextAdd(sharedStruct.Enc memory _ctx1, sharedStruct.Enc memory _ctx2) public view returns (sharedStruct.Enc memory result){
        (result.Cval.x, result.Cval.y)= eAdd(_ctx1.Cval.x, _ctx1.Cval.y, _ctx2.Cval.x, _ctx2.Cval.y);
        (result.Rval.x, result.Rval.y)= eAdd(_ctx1.Rval.x, _ctx1.Rval.y, _ctx2.Rval.x, _ctx2.Rval.y);
    }

    function otpEncrypt(sharedStruct.Enc memory _ctx, uint256 key) public view returns (sharedStruct.Enc memory cipher){
        (cipher.Cval.x, cipher.Cval.y)=eAdd(_ctx.Cval.x, _ctx.Cval.y, key, key);
        (cipher.Rval.x, cipher.Rval.y)=eAdd(_ctx.Rval.x, _ctx.Rval.y, key, key);
    }

    function otpDecrypt(sharedStruct.Enc memory _ctx, uint256 key) public view returns (sharedStruct.Enc memory cipher){
        uint256 k1;
        uint256 k2;
        (k1,k2)= eInv(key, key);
        (cipher.Cval.x, cipher.Cval.y)=eAdd(_ctx.Cval.x, _ctx.Cval.y, k1, k2);
        (cipher.Rval.x, cipher.Rval.y)=eAdd(_ctx.Rval.x, _ctx.Rval.y, k1, k2);
    }

 function removeRandomness(sharedStruct.point memory _pt, sharedStruct.Enc memory _ctx) public view returns (sharedStruct.Enc memory cipher){
        uint256 r1;
        uint256 r2;
        (r1,r2)= eInv(_pt.x, _pt.y);
        (cipher.Cval.x, cipher.Cval.y)=eAdd(_ctx.Cval.x, _ctx.Cval.y, r1, r2);
        (cipher.Rval.x, cipher.Rval.y)=eAdd(_ctx.Rval.x, _ctx.Rval.y, r1, r2);
    }

function genPubkey(address _party, uint256 gx, uint256 gy) public view returns (uint256 pkx, uint256 pky){
    (pkx, pky)=eMul(uint256(sha256(abi.encodePacked(_party))), gx, gy);
}

function test() public pure returns (bool res){
    res=true;
}

function genpoint(uint256 r, uint256 gx, uint256 gy) public view returns (uint256 rx, uint256 ry){
    (rx, ry)=eMul(r, gx, gy);
}


function CiphertextCompare(sharedStruct.Enc memory _ctx1, sharedStruct.Enc memory _ctx2) public pure returns (bool flag){
        if(_ctx1.Cval.x== _ctx2.Cval.x && _ctx1.Cval.y== _ctx2.Cval.y){
            if (_ctx1.Rval.x== _ctx2.Rval.x && _ctx1.Rval.y== _ctx2.Rval.y){
                flag=true;
            }
            else{
                flag=false;
            }
        }
        else{
            flag=false;
        }
    }


function Generatesubkeys(uint256 key, uint256 _Traceindex, uint256[] memory _compidx) public pure returns (uint256[] memory vk){
        for (uint i=0; i<_compidx.length ; i++)
            {
                vk[i]=uint256(sha256(abi.encodePacked(key,_Traceindex,_compidx[i])));
            }
    }

function HCommit(uint256 _r, uint256 _m) public pure returns (uint256 com){
         com=uint256(sha256(abi.encodePacked(_m,_r)));
    }

function VerifyHCommit(uint256 _r, uint256 _m, uint256 _com) public pure returns (bool result){
         uint256 c;
         c=HCommit(_r, _m);
         if(c ==_com){
            result = true;
         }
         else{
            result = false;
         }
    }

function ElgamalEnc(uint256 _m, uint256 _r, sharedStruct.point memory _pk) public view returns (sharedStruct.point memory C, sharedStruct.point memory R){

        ( uint256 _x1, uint256  _y1 ) = eMul( _m , gx , gy );
        ( uint256 _x2, uint256 _y2 ) = eMul( _r , _pk.x , _pk.y );
        ( R.x, R.y ) = eMul( _r , gx , gy );
        ( C.x, C.y ) = eAdd( _x1 , _y1 , _x2 , _y2 );
    }

function ElgamalDec(sharedStruct.point memory _c, sharedStruct.point memory _r, uint256 _s1) public view returns (sharedStruct.point memory mg){
        ( uint256 _x1, uint256  _y1 ) = eMul( _s1 , _r.x , _r.y );
        ( uint256 _x2, uint256 _y2 ) = eInv( _x1 , _y1);
        ( mg.x, mg.y ) = eAdd( _c.x , _c.y , _x2 , _y2 );
}

function RencZKP(sharedStruct.Enc memory cipher1, uint256 _sk1, sharedStruct.point memory _pk2) public view returns(sharedStruct.Enc memory enc, sharedStruct.ZKP memory proof)
{
    uint256 rnew;
    (enc,rnew)= Reencrypt(cipher1.Cval,cipher1.Rval,_sk1,_pk2);
    uint256 s=random(enc.Cval.x);
    uint256 ss=random(enc.Rval.x);
    (proof.a1.x , proof.a1.y) = eMul(submodP(s,ss), gx, gy);
    (proof.a2.x , proof.a2.y) = eMul(s, cipher1.Rval.x, cipher1.Rval.y);
    (proof.a3.x , proof.a3.y) = eMul(ss, _pk2.x, _pk2.y);
    uint256 e=uint256(sha256(abi.encodePacked(proof.a1.x,proof.a2.x,proof.a3.x)));
    proof.rhat=addmodP(s,mulmod(e,_sk1,pp));
    proof.rr=addmodP(ss,mulmod(e,rnew,pp));
    }

 function RencZKPVerify(sharedStruct.Enc memory enc1, sharedStruct.point memory pk1, sharedStruct.Enc memory enc2, sharedStruct.point memory pk2, sharedStruct.ZKP memory proof) public view returns (bool result)
{
    uint256 e=uint256(sha256(abi.encodePacked(proof.a1.x,proof.a2.x,proof.a3.x)));
    //uint256 tmp01=(pk2.expmod(rr,P)).invmod(P);
    //uint256 tmp02= C1.expmod(rhat,P);

    (uint256 tmp1x,uint256 tmp1y) = ZKPverifyHelper1(enc1, pk2, proof);
    //delete tt1x;
    //delete tt1y;
    (uint256 tmp2x, uint256 tmp2y)=ZKPverifyHelper2(enc1, enc2, e, proof);
    //delete temp1x;
    //delete temp1y;

    if  (tmp1x == tmp2x && tmp1y == tmp2y) {
            ( uint256 tmp3x, uint256 tmp3y)= eMul(submodP(proof.rhat,proof.rr), gx ,gy);
            (uint256 tmp4x, uint256 tmp4y)=ZKPverifyHelper3(pk1, enc2, e, proof);


             if  (tmp3x == tmp4x && tmp3y == tmp4y) {
                 result = true;
            }
            else {
                result = false;
            }
        }
        else{
            result = false;
        }

}

function ZKPverifyHelper1(sharedStruct.Enc memory enc1, sharedStruct.point memory pk2, sharedStruct.ZKP memory proof) internal view returns (uint256 tmp1x,uint256 tmp1y){
    (uint256 temp1x, uint256 temp1y) = eMul(proof.rr, pk2.x, pk2.y);
    (uint256 tt1x, uint256 tt1y) = eMul(proof.rhat, enc1.Rval.x, enc1.Rval.y);
    (uint256 temp2x, uint256 temp2y) = eInv(tt1x, tt1y);
    (tmp1x,tmp1y) = eAdd(temp1x, temp1y, temp2x, temp2y);
}

function ZKPverifyHelper2(sharedStruct.Enc memory enc1, sharedStruct.Enc memory enc2, uint256 e, sharedStruct.ZKP memory proof) internal view returns (uint256 tmp2x,uint256 tmp2y){
    (uint256 temp1x, uint256 temp1y) = eInv(proof.a2.x, proof.a2.y);
    (uint256 temp2x, uint256 temp2y) = eAdd(proof.a3.x, proof.a3.y,temp1x, temp1y);
    (temp1x, temp1y) = eInv(enc1.Cval.x, enc1.Cval.y);
    (uint256 temp3x, uint256 temp3y) = eAdd(enc2.Cval.x, enc2.Cval.y, temp1x, temp1y);
    (temp1x, temp1y) = eMul(e, temp3x, temp3y);
    (tmp2x, tmp2y)=eAdd(temp2x, temp2y,temp1x, temp1y);
}


function ZKPverifyHelper3(sharedStruct.point memory pk1, sharedStruct.Enc memory enc2, uint256 e, sharedStruct.ZKP memory proof) internal view returns (uint256 tmp4x,uint256 tmp4y){
           //( uint256 tmp3x, uint256 tmp3y)= eMul(submodP(proof.rhat,proof.rr), gx ,gy);
            (uint256 temp1x, uint256 temp1y) = eInv(enc2.Rval.x, enc2.Rval.y);
            (uint256 temp2x, uint256 temp2y) = eAdd(pk1.x, pk1.y, temp1x, temp1y);
            ( temp1x, temp1y) = eMul(e,temp2x, temp2y);
            (tmp4x, tmp4y)=eAdd(proof.a1.x, proof.a1.y,temp1x, temp1y);
}

function Reencrypt(sharedStruct.point memory _c, sharedStruct.point memory _r, uint256 _s, sharedStruct.point memory _pknew) internal view returns (sharedStruct.Enc memory enc, uint256 rnew){

    sharedStruct.point memory _mg = ElgamalDec(_c, _r, _s);
    rnew=random(_r.x);
    ( uint256 _x1 , uint256  _y1 ) = eMul( rnew , _pknew.x , _pknew.y );
    ( enc.Cval.x, enc.Cval.y ) = eAdd( _mg.x , _mg.y , _x1 , _y1 );
    ( enc.Rval.x , enc.Rval.y ) = eMul( rnew , gx , gy );

}

function random(uint256 _r) internal view returns (uint256 rand){
    rand=uint256(keccak256(abi.encodePacked(block.timestamp,_r)));
}


function PlaintextZKP(sharedStruct.Enc memory enc, uint256 _m, uint256 _r, sharedStruct.point memory _Pk) public view returns(sharedStruct.ptxtZKP memory proof)
{

    uint256 s=random(enc.Cval.x);
    uint256 ss=random(enc.Rval.x);
    (proof.a1, proof.a2) = ElgamalEnc(s, ss, _Pk);
    uint256 e=uint256(sha256(abi.encodePacked(proof.a1.x,proof.a2.x)));
    proof.rhat=addmodP(s,mulmod(e,_m,pp));
    proof.rr=addmodP(ss,mulmod(e,_r,pp));
    }

function VerifyPlaintextZKP(sharedStruct.Enc memory enc, sharedStruct.point memory _Pk, sharedStruct.ptxtZKP memory proof) public view returns(bool result)
{

    uint256 e=uint256(sha256(abi.encodePacked(proof.a1.x,proof.a2.x)));
            (uint256 tmp1x, uint256 tmp1y)= eMul(e, enc.Rval.x, enc.Rval.y);
            (uint256 tmp2x, uint256 tmp2y)= eAdd(proof.a2.x, proof.a2.y,tmp1x, tmp1y);
            (uint256 tmp3x, uint256 tmp3y)= eMul(proof.rr, gx, gy);
             if  (tmp2x == tmp3x && tmp2y == tmp3y) {
                  (tmp1x, tmp1y)= eMul(e, enc.Cval.x, enc.Cval.y);
                  (uint256 tmp4x, uint256 tmp4y)= eAdd(proof.a1.x, proof.a1.y,tmp1x, tmp1y);
                  //(tmp1x, tmp1y)= eMul(proof.rhat, gx, gy);
                  //(uint256 tmp5x, uint256 tmp5y)= eMul(proof.rr, _Pk.x, _Pk.y);
                  (uint256 tmp6x, uint256 tmp6y)= pltxZKPverifyHelper1(_Pk, proof);
                  if  (tmp4x == tmp6x && tmp4y == tmp6y) {
                    result = true;
                    }
                    else {
                        result = false;
                        }
                        }
                else{
                         result = false;
                            }
    }


function pltxZKPverifyHelper1(sharedStruct.point memory _Pk, sharedStruct.ptxtZKP memory proof) internal view returns (uint256 tmp6x,uint256 tmp6y){
                  (uint256 tmp1x, uint256 tmp1y)= eMul(proof.rhat, gx, gy);
                  (uint256 tmp5x, uint256 tmp5y)= eMul(proof.rr, _Pk.x, _Pk.y);
                  (tmp6x,tmp6y)= eAdd(tmp1x, tmp1y,tmp5x, tmp5y );
}


function generateMerkleRoot(uint256[] memory _hashes) public pure returns (uint256) {
        uint256[] memory prevL = _hashes;
        uint256[] memory nextLayer;
        while (prevL.length > 1) {
            uint256[] memory nextL = new uint256[]((prevL.length + 1) / 2);
            for (uint256 i = 0; i < nextL.length; i++) {
                if (2 * i + 1 < prevL.length) {
                    nextLayer[i] = uint256(sha256(abi.encodePacked(prevL[2 * i], prevL[2 * i + 1])));
                } else {
                    nextL[i] = prevL[2 * i];
                }
            }
            prevL = nextL;
        }
        return prevL[0];
    }

    function calculateMerkleRoot(
        uint256[] memory nodes,
        uint256 index,
        uint256 leaf
    ) internal pure returns (uint256) {
        uint256 proofItems = nodes.length;
        require(proofItems <= 256);
        uint256 h = leaf;
        for (uint256 i = 0; i < proofItems; i++) {
            if (index % 2 != 0) {
                h = uint256(sha256(abi.encodePacked(nodes[i], h)));
            } else {
                h = uint256(sha256(abi.encodePacked(h, nodes[i])));
            }
            //index /= 2;
        }
        return h;
    }

    function calRootonMerkleProof(
        uint256 index,
        uint256[] memory proof
    ) public pure returns (uint256) {
        uint256 proofItems = proof.length;
        require(proofItems <= 256);
        uint256 h = proof[0];
        for (uint256 i = 1; i < proofItems; i++) {
            if (index % 2 != 0) {
                h = uint256(sha256(abi.encodePacked(proof[i], h)));
            } else {
                h = uint256(sha256(abi.encodePacked(h, proof[i])));
            }
            //index /= 2;
        }
        return h;
    }


    function HashingCommitment(sharedStruct.point memory _com) public pure returns (uint256){
        uint256 h = uint256(sha256(abi.encodePacked(_com.x, _com.y)));
        return h;

    }

    function HashingGate(uint256 _gidx, uint256[] memory _compidx) public pure returns (uint256){
        uint256 h=uint256(sha256(abi.encodePacked(_gidx, _compidx[0], _compidx[1], _compidx[2])));
        return h;
    }

    function HashingTrace(uint256 _Traceindex, uint256 _compidx, sharedStruct.Enc memory _ctx) public pure returns (uint256){
        uint256 h=uint256(sha256(abi.encodePacked(_Traceindex,_compidx,_ctx.Cval.x,_ctx.Cval.y,_ctx.Rval.x,_ctx.Rval.y)));
        return h;
    }

    function HashingEncryption(sharedStruct.Enc memory _ctx) public pure returns (uint256){
        uint256 h = uint256(sha256(abi.encodePacked(_ctx.Cval.x, _ctx.Cval.y, _ctx.Rval.x, _ctx.Rval.y)));
        return h;

    }

    function HashingVector(uint256 _vec) public pure returns (uint256){
        uint256 h;
        for (uint256 i = 0; i < 1; i++) {
            h = uint256(sha256(abi.encodePacked(_vec)));
        }
        return h;

    }

function verifyMerkleProof(uint256 root, uint256 leaf, uint256[] memory _merkleleaves, uint256 _index) public pure returns (bool success) {
        uint256 Mroot = calculateMerkleRoot(_merkleleaves, _index, leaf);
        if(root == Mroot){
            success=true;
        }else{
            success=false;
        }
}


}
