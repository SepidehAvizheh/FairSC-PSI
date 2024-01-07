// SPDX-License-Identifier: sharedStruct.sol
pragma solidity >=0.4.22<0.8.22;
pragma experimental ABIEncoderV2;

library sharedStruct{

struct point{
        uint256 x;
        uint256 y;
    }

    struct Enc{
         point Cval;
         point Rval;
         }

    struct ZKP{
        point a1;
        point a2;
        point a3;
        uint256 rhat;
        uint256 rr;
        }

    struct ptxtZKP{
        point a1;
        point a2;
        uint256 rhat;
        uint256 rr;
        }

    struct Gid{
        uint256 inId1;
        uint256 inId2;
        uint256 gId;
        uint256 oId;
}

function Init() public view returns(bool){
  return true;
}

}
