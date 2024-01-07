// SPDX-License-Identifier: SCPSIEC.sol
pragma solidity >=0.4.22<0.8.22;
pragma experimental ABIEncoderV2;
import "./CryptoLib.sol";
import "./sharedStruct.sol";

contract SCPSIEC{

using sharedStruct for uint256;

    enum State {INIT, POLYRECEIVE, COMMITMENT, REENCRYPTION, OPENING, JUDGE, ABORT, TERMINATED}
  State public state;
  CryptoLib public _CryptoLib;

 mapping(uint => address) public party;



uint count=0;

uint amount;
uint256 MRoot;

mapping (uint => sharedStruct.point) partykey;
mapping (uint256 => sharedStruct.point) commits;

mapping (uint256 => sharedStruct.Enc) Ctx2;

mapping (uint256 => sharedStruct.ZKP) Pk;

uint256 Mroot;

uint256[] r;
uint256[] v;


uint256 public gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
uint256 public gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;





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

  function setup(address _party, uint256 _amount) public returns(bool){
      count=count+1;
      party[count]=_party;
      (partykey[count].x, partykey[count].y)= _CryptoLib.genPubkey(_party, gx, gy);
      amount=_amount;
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

function Receive(uint _st) public onlyParty2 returns (bool flag){
    if(state==State.POLYRECEIVE){
        if(_st==1){
            state=State.COMMITMENT;
            flag=true;
        }
        else{
            state=State.ABORT;
            transfer(msg.sender,amount);
            flag=false;
        }
    }
    else{
         flag=false;
         }
}


function Commitment(sharedStruct.point[] memory _coms, uint256 _Mroot) public onlyParty2 returns (bool flag){
    if(state==State.COMMITMENT){
        //sharedStruct.point[] storage commits;
        for (uint256 idx=0; idx<_coms.length; idx++)
        {
            commits[idx]=_coms[idx];
        }
        Mroot=_Mroot;
        state=State.REENCRYPTION;
        flag=true;
    }
    else{
        flag=false;
    }

}

function ReencryptZKP(sharedStruct.Enc[] memory _Ctx2, sharedStruct.ZKP[] memory _Pk) public onlyParty1 returns(bool flag){
    if(state==State.REENCRYPTION){
        for (uint256 idx=0; idx<_Ctx2.length; idx++)
        {
            Ctx2[idx]=_Ctx2[idx];
        }
        for (uint256 idx=0; idx<_Pk.length; idx++)
        {
            Pk[idx]=_Pk[idx];
        }
        state=State.OPENING;
        flag=true;
    }
    else{
        flag=false;
    }
}


function Opening(uint256[] memory _r, uint256[] memory _v) public onlyParty2 returns(bool flag){
    if(state==State.OPENING){
        r=_r;
        v=_v;
        state=State.JUDGE;
        flag=true;
    }
    else{
        flag=false;
    }
}


function Judge(uint256 _idx, string memory _st) public returns (bool flag){
    if(msg.sender==party[1]){
        //Party 1 accepts
        if(keccak256(abi.encodePacked(_st))==keccak256(abi.encodePacked("accept")) && state==State.JUDGE )
        {
            transfer(party[2],amount);
            emit FairPSI("Complete Fairness");
            //state=State.TERMINATED;
            flag=true;
        }
        //Party 2 aborts and party 2 complains about abort
        else if(keccak256(abi.encodePacked(_st))==keccak256(abi.encodePacked("abort")) && state==State.OPENING)
        {
            transfer(msg.sender,amount);
            emit FairPSI("Coin Compensated Fairness");
            //state=State.TERMINATED;
            flag=true;
        }
        else if(keccak256(abi.encodePacked(_st))==keccak256(abi.encodePacked("IncorrectOpening")) && state==State.JUDGE){
           bool result = _CryptoLib.verify(r[_idx], v[_idx],commits[_idx].x,commits[_idx].y);
           if(result==true)
           {
               transfer(party[2],amount);
               emit FairPSI("Complete Fairness");
               //state=State.TERMINATED;
               flag=false;
           }
           else{
               transfer(msg.sender,amount);
                emit FairPSI("Coin Compensated Fairness");
                //state=State.TERMINATED;
               flag=true;
           }

        }
        else
        {
            flag=false;
        }

    }
    if(msg.sender==party[2]){
        if(keccak256(abi.encodePacked(_st))==keccak256(abi.encodePacked("Refund")) && (state != State.OPENING || state!=State.JUDGE)){
            transfer(msg.sender,amount);
            emit FairPSI("Complete Fairness");
            //state=State.TERMINATED;
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


    function JudgeIncorrectReenc(uint256 _idx, sharedStruct.Enc memory _ctx1, uint256[] memory MProof) public onlyParty2  returns (bool flag){
          if(state == State.OPENING ||state==State.JUDGE){
            bool result;
            uint256 leaf;
            leaf=uint256(sha256(abi.encodePacked(_ctx1.Cval.x,_ctx1.Cval.y,_ctx1.Rval.x,_ctx1.Rval.y)));
            result= _CryptoLib.verifyMerkleProof(Mroot, leaf, MProof, _idx);
            if(result==true){
                bool result2;
                result2= _CryptoLib.RencZKPVerify(_ctx1, partykey[1], Ctx2[_idx], partykey[2], Pk[_idx]);
                if(result2==false){
                     transfer(msg.sender,amount);
                     emit FairPSI("Complete fairness");
                     //state=State.TERMINATED;
                     flag=true;
                }
                else{
                    transfer(party[1],amount);
                    emit FairPSI("Coin compensated PSI");
                    //state=State.TERMINATED;
                    flag=false;
                }
            }
            else{
                transfer(party[1],amount);
                emit FairPSI("Coin compensated PSI");
                state=State.TERMINATED;
                flag=false;
            }

          }
    }

}
