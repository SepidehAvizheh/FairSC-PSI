// SPDX-License-Identifier: SCPSIEC.sol
pragma solidity >=0.4.22<0.8.22;
pragma experimental ABIEncoderV2;
import "./CryptoLib.sol";
import "./sharedStruct.sol";

contract SCPSI2EC{

using sharedStruct for uint256;

    enum State { INIT, POLYRECEIVE, COMMITMENT, REENCRYPTION, OPENING, JUDGE, ABORT, TERMINATED}
  State public state;
  CryptoLib public _CryptoLib;


 mapping(uint => address) public party;

uint256 public gx = uint256(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798);
uint256 public gy = uint256(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8);



 uint count=0;

uint amount;
uint256[] com;
uint256[] comkey;
uint256 e;
uint256[] y;
uint256[] r;
uint256[] v;

uint256 Mrphi;


mapping (uint => sharedStruct.point) partykey;
mapping (uint => sharedStruct.Enc) Ctx2;
mapping (uint => sharedStruct.Enc) ciphertexts1;
mapping (uint => sharedStruct.Enc) ciphertexts2;
mapping (uint => sharedStruct.ZKP) proof;

mapping (uint => sharedStruct.Enc) Trace1;

mapping (uint => sharedStruct.Enc) Trace2;

uint256[] rkey;
uint256[] vkey;
uint256 rootd;







  modifier onlyParty1 {
      require(msg.sender == party[1]);
      _;
  }

   modifier onlyParty2 {
      require(msg.sender == party[2]);
      _;
  }

event DepositMade(address sender, uint value);

event FairPSI(string);

function Hack(CryptoLib _clib) public {
        _CryptoLib = _clib;
    }

  function setup(address _party, uint _amount) public returns(bool){
      count=count+1;
      party[count]=_party;
      amount=_amount;
      (partykey[count].x, partykey[count].y)= _CryptoLib.genPubkey(_party, gx, gy);
      state=State.INIT;
      return true;
  }



function Init() public payable onlyParty2 returns(bool flag) {
    if(state==State.INIT){
        if(msg.value>=amount){
            state=State.POLYRECEIVE;
            emit DepositMade(msg.sender,msg.value);
            flag=true;
        }
        else{
            transfer(msg.sender,msg.value);
            state=State.TERMINATED;
            flag=false;

        }
    }
    else{
        flag=false;
    }
}

function Receive(uint256 _rootphi, uint256 _rootd) public onlyParty2 returns (bool flag){
    Mrphi=_rootphi;
    rootd=_rootd;
    if(state==State.POLYRECEIVE){
         state=State.COMMITMENT;
         flag=true;
    }
    else{
         flag=false;
         }
}


function Commitment(uint256[] memory _com, uint256[] memory _comkey, uint256[] memory _ry, uint256 _re) public onlyParty2 returns (bool flag){

    if(state==State.COMMITMENT){
        com=_com;
        comkey=_comkey;
        e=_re;
        y=_ry;
        state=State.REENCRYPTION;
        flag=true;
    }
    else{
        flag=false;
    }

}

function ReencryptZKP(sharedStruct.Enc[] memory _ctx2, sharedStruct.Enc memory _agg1, sharedStruct.Enc memory _agg2, sharedStruct.ZKP memory _proof, sharedStruct.Enc[] memory _TracePk1, sharedStruct.Enc[] memory _TracePk2) public onlyParty1 returns(bool flag){
    if(state==State.REENCRYPTION){
        for (uint i=0; i<_ctx2.length; i++)
        {
            Ctx2[i]= _ctx2[i];
            Trace1[i]=_TracePk1[i];
            Trace2[i]= _TracePk2[i];
        }
        ciphertexts1[0].Cval=_agg1.Cval;
        ciphertexts1[0].Rval=_agg1.Rval;
        ciphertexts2[0].Cval=_agg2.Cval;
        ciphertexts2[0].Rval=_agg2.Rval;
        proof[0]=_proof;
        state=State.OPENING;
        flag=true;
    }
    else{
        flag=false;
    }
}


function Opening(uint256[] memory _r, uint256[] memory _v, uint256[] memory _rkey, uint256[] memory _vkey) public onlyParty2 returns(bool flag){
    if(state==State.OPENING){
        r=_r;
        v=_v;
        rkey=_rkey;
        vkey=_vkey;
        state=State.JUDGE;
        flag=true;
    }
    else{
        flag=false;
    }
}


function Judge2(uint256 _idx, string memory _st) public returns (bool flag){
    if(msg.sender==party[1]){
        //Party 1 accepts
        if(keccak256(abi.encodePacked(_st))==keccak256(abi.encodePacked("accept")) && state==State.JUDGE )
        {
            transferCFair(party[2],amount);
            flag=true;
        }
        //Party 2 aborts and party 2 complains about abort
        else if(keccak256(abi.encodePacked(_st))==keccak256(abi.encodePacked("abort")) && state==State.OPENING)
        {
            transferCCP(msg.sender,amount);
            flag=true;
        }
        else if(keccak256(abi.encodePacked(_st))==keccak256(abi.encodePacked("IncorrectOpening")) && state==State.JUDGE){
           bool result = _CryptoLib.VerifyHCommit(r[_idx], v[_idx],com[_idx]);
           if(result==true)
           {
               transferCFair(party[2],amount);
               flag=false;
           }
           else{
               transferCCP(msg.sender,amount);
               flag=true;
           }

        }
        else
        {
            flag=false;
        }

    }
    if(msg.sender==party[2]){
        if(keccak256(abi.encodePacked(_st))==keccak256(abi.encodePacked("Refund")) && (state != State.OPENING || state !=State.JUDGE)){
            transferCFair(msg.sender,amount);
            flag=true;
        }
      }

    }



 //if (Time_call()-T >= RoundTime){
      //   state=State.OPENING;
       //  firstcome=0;
     //}



function transfer(address _to, uint _amount) internal returns (bool success){
    //(success, )=_to.call{value: _amount}("");
    (success, )=_to.call.value(_amount)(" ");
    }


function transferCCP(address _to, uint _amount) internal{
    transfer(_to,_amount);
    emit FairPSI("Coin compensated PSI");
    //state=State.TERMINATED;
}

function transferCFair(address _to, uint _amount) internal {
    transfer(_to,_amount);
    emit FairPSI("Complete Fairness");
    //state=State.TERMINATED;
}

    function JudgeIncorrectAggReenc() public onlyParty2  returns (bool flag){

          if(state == State.OPENING ||state==State.JUDGE){
                bool result;
                result= _CryptoLib.RencZKPVerify(ciphertexts1[0], partykey[1], ciphertexts2[0], partykey[2], proof[0]);
                if(result==false){
                     transferCFair(msg.sender,amount);
                     flag=true;
                }
                else{
                    transferCCP(party[1],amount);
                    flag=false;
                }

          }
    }

    function JudgeIncorrectAgg1Compute(uint256[] memory _idx, sharedStruct.Enc memory _ctx1, uint256[] memory _MPCtx) public onlyParty2  returns (bool flag){

          if(state == State.OPENING ||state==State.JUDGE){

            bool result;
            uint256 leaf;
                leaf=uint256(sha256(abi.encodePacked(_ctx1.Cval.x,_ctx1.Cval.y,_ctx1.Rval.x,_ctx1.Rval.y)));
                result= _CryptoLib.verifyMerkleProof(e, leaf, _MPCtx, _idx[0]);

                if(result==true){
                    sharedStruct.Enc memory temp;
                    temp= _CryptoLib.CiphertextAdd(_ctx1,Trace1[_idx[1]]);
                    bool flag1= _CryptoLib.CiphertextCompare(temp, Trace1[_idx[2]]);
                    if(flag1 == false){
                        transferCFair(msg.sender,amount);
                        flag=true;
                    }
                    else{
                        transferCCP(party[1],amount);
                        flag=false;
                    }
                }
                else{
                    transferCCP(party[1],amount);
                    flag=false;
                }
          }
    }



 function JudgeIncorrectAgg2Compute(uint256[] memory _idx) public onlyParty2  returns (bool flag){

          if(state == State.OPENING ||state==State.JUDGE){
            sharedStruct.Enc memory temp;
            temp= _CryptoLib.CiphertextAdd(Ctx2[_idx[0]],Trace2[_idx[1]]);
            flag= _CryptoLib.CiphertextCompare(temp, Trace2[_idx[2]]);
             if(flag == true){
                transferCFair(msg.sender,amount);
                 }
             else{
                 transferCCP(party[1],amount);
                 }
          }
    //      else{
     //       transfer(party[1],amount);
    //        emit FairPSI("Coin compensated PSI");
     //       state=State.TERMINATED;
     //       flag=false;
     //       }
    }



    function JudgeIncorrectPolyEval(uint _Traceindex, uint256 _gidx, uint256[] memory _compidx, sharedStruct.Enc[] memory _ctxs,  uint256[][] memory _MPCtxs, uint256[] memory _MPgate) public onlyParty1  returns (bool flag){
          //Gid memory gateinfo= Gid({gId:_gidx, in1:_compidx[0], in2: _compidx[1], out:_compidx[2]});
          if(state==State.JUDGE){
             uint256[] memory leaf;
            bool[] memory result;
            sharedStruct.Enc[] memory cipher;
            leaf[0]=uint256(sha256(abi.encodePacked(_gidx, _compidx[0], _compidx[1], _compidx[2])));
            result[0]= _CryptoLib.verifyMerkleProof(Mrphi, leaf[0], _MPgate, _gidx);
            (result[1],cipher)= VerifyCipherTrace(_Traceindex,_compidx,_ctxs,_MPCtxs);

                if(result[0]==true && result[1]==true){
                    sharedStruct.Enc memory temp;
                      temp= _CryptoLib.CiphertextAdd(cipher[0],cipher[1]);
                    bool flag1= _CryptoLib.CiphertextCompare(temp, cipher[2]);
                    if(flag1 == false){
                        transferCCP(msg.sender,amount);
                        flag=true;
                    }
                    else{
                        transferCFair(party[2],amount);
                        flag=false;
                    }
                }
                else{
                    transferCFair(party[2],amount);
                    flag=false;
                     }
                }
    }

     function JudgeIncorrectInputPolyEval(uint _Traceindex, uint256[] memory _compidx, uint256[] memory _coeffidx, sharedStruct.Enc[] memory _ctxs, sharedStruct.Enc[] memory _coeff,  uint256[][] memory _MPCtxs, uint256[][] memory _MPCoeff) public onlyParty1  returns (bool flag){
             if(state==State.JUDGE){
                 bool flag1=false;
                 bool res;
            sharedStruct.Enc[] memory cipher;
            (flag,cipher)= VerifyCipherTrace(_Traceindex,_compidx,_ctxs,_MPCtxs);
            if(flag==true){
                for (uint i=0; i<_coeff.length; i++)
            {
                flag= VerifyCoeffTrace(_coeffidx,_coeff,_MPCoeff);
                res=_CryptoLib.CiphertextCompare(cipher[i],_coeff[i]);
                if(res==false){
                    flag1=true;
                }
            }
                if(flag == true && flag1==true){
                        transferCCP(msg.sender,amount);
                    }
                else{
                        transferCFair(party[2],amount);
                    }
            }
            else{
                 transferCFair(party[2],amount);
                //flag=false;
                }

  }
}

function VerifyCipherTrace(uint _Traceindex, uint256[] memory _compidx, sharedStruct.Enc[] memory _ctxs,  uint256[][] memory _MPCtxs) internal view returns (bool flag, sharedStruct.Enc[] memory cipher){
           flag=true;
            uint256[] memory leaf;
            bool[] memory result;
            uint256[] memory vkeys= _CryptoLib.Generatesubkeys(vkey[_Traceindex],_Traceindex,_compidx);
            cipher= DecryptCtx(_ctxs,vkeys);
            for (uint i=0; i<_ctxs.length; i++)
            {
                leaf[i]=uint256(sha256(abi.encodePacked(_Traceindex,_compidx[i],_ctxs[i].Cval.x,_ctxs[i].Cval.y,_ctxs[i].Rval.x,_ctxs[i].Rval.y)));
                result[i]= _CryptoLib.verifyMerkleProof(y[_Traceindex], leaf[i], _MPCtxs[i], _compidx[i]);
                if(result[i]==false){
                    flag=false;
                }
            }
}

function VerifyCoeffTrace(uint256[] memory _coeffidx, sharedStruct.Enc[] memory _coeff,  uint256[][] memory _MPCoeff) internal view returns (bool flag){
           flag=true;
            uint256[] memory leaf;
            bool[] memory result;
            for (uint i=0; i<_coeff.length; i++)
            {
                leaf[i]=uint256(sha256(abi.encodePacked(_coeffidx[i], _coeff[i].Cval.x,_coeff[i].Cval.y,_coeff[i].Rval.x,_coeff[i].Rval.y)));
                result[i]= _CryptoLib.verifyMerkleProof(rootd, leaf[i], _MPCoeff[i], _coeffidx[i]);
                if(result[i]==false){
                    flag=false;
                }
            }
}


    function DecryptCtx(sharedStruct.Enc[] memory _ctxs, uint256[] memory vkeys) public view returns (sharedStruct.Enc[] memory temp){
        for (uint i=0; i<_ctxs.length; i++)
        {
            temp[i]=_CryptoLib.otpDecrypt(_ctxs[i],vkeys[i]);
            }
    }

    function JudgeKeyTrNotOpen(uint256 _index, sharedStruct.Enc memory _ctx1,  uint256[] memory _MProof, sharedStruct.ptxtZKP memory _Zkproof) public onlyParty1  returns (bool flag){
          if(state==State.JUDGE){
            uint256 leaf;
            bool result;
            leaf=uint256(sha256(abi.encodePacked(_ctx1.Cval.x,_ctx1.Cval.y,_ctx1.Rval.x,_ctx1.Rval.y)));
            result= _CryptoLib.verifyMerkleProof(e, leaf, _MProof, _index);
            if(result==true && vkey[_index] == 0){
                // vkey[] for the indexes that are not going to be opened is set to 0
                sharedStruct.point memory blfactor;
                (blfactor.x, blfactor.y)=_CryptoLib.genpoint(v[_index], gx, gy);
                sharedStruct.Enc memory _ctx= _CryptoLib.removeRandomness(blfactor,_ctx1);
                flag= _CryptoLib.VerifyPlaintextZKP(_ctx, partykey[1], _Zkproof);
                if(flag == true){
                        transferCCP(msg.sender,amount);
                        flag=true;
                    }
                else{
                        transferCFair(party[2],amount);
                        flag=false;
                    }
            }
                else{
                    transferCFair(party[2],amount);
                    flag=false;
                }
          }
    }

    function JudgeOutputNotZero(uint256 _Traceindex, uint256[] memory _oidx, uint256 _comindex, sharedStruct.Enc[] memory _ctx, uint256[][] memory _MProof) public onlyParty1  returns (bool flag){
         if(state==State.JUDGE){
            //Comment: _ctx[0] wire 13 (output), _ctx[1] is wire 12
            bool result;
            sharedStruct.Enc[] memory cipher;
            (result,cipher)= VerifyCipherTrace(_Traceindex,_oidx,_ctx,_MProof);
            if(result==true){
                    sharedStruct.point memory blfactor;
                    (blfactor.x, blfactor.y)=_CryptoLib.genpoint(v[_comindex], gx, gy);
                    sharedStruct.Enc memory _ctxUnblind= _CryptoLib.removeRandomness(blfactor,cipher[0]);
                    if(cipher[1].Cval.x== _ctxUnblind.Cval.x && cipher[1].Cval.y== _ctxUnblind.Cval.y && cipher[1].Rval.x== _ctxUnblind.Rval.x && cipher[1].Rval.y== _ctxUnblind.Rval.y){
                        transferCCP(msg.sender,amount);
                        flag=true;
                    }
                    else{
                        transferCFair(party[2],amount);
                        flag=false;
                    }

            }
            else{
                        transferCFair(party[2],amount);
                        flag=false;
                    }

            }
    }
}
