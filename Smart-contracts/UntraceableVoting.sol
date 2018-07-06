pragma solidity ^0.4.2;


library SafeMath {
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }
    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = a + b;
        assert(c >= a);
        return c;
    }
}

interface secp256k {

  function ScalarMult(uint256 px,uint256 py, uint256 scalar) view external returns(uint256 qx, uint256 qy);
  
  function ScalarBaseMult(uint256 scalar) view external returns(uint256 qx, uint256 qy);
    
  function HashToEcc(uint256 x1,uint256 y1) view external returns (uint256 qx,uint256 qy);

  function Add( uint256 x1,uint256 y1,   uint256 x2,uint256 y2) view external returns    (uint256 x3,uint256 y3);
}

contract UntraceableVoting{
    secp256k Curve;
    address owner;
    mapping(uint256=>voting) public votings;
    
    constructor(address curveDest) public{
        require(curveDest!=address(0));
        Curve = secp256k(curveDest);
        owner = msg.sender;
    }
    
     function createVote(uint64 id,  address[] candidatesIDs)  public payable {
         require(votings[id].id == 0);
        require(id != 0);
        votings[id] = voting(msg.sender,candidatesIDs, id,  msg.value,1,0,new uint256[](0),new uint256[](0),false,false);
        
        //fill the mapping and set each candidate on a start value of 1;
        for(uint i=0;i< candidatesIDs.length;i++){
            //this require assures that no candidate is listed twice very efficiently
            require( votings[id].candidates[candidatesIDs[i]]==0);
            votings[id].candidates[candidatesIDs[i]]=1;
        }
        
    }
    
    function addVotersToVote(uint64 id, uint256[] allowedVotersX,uint256[] allowedVotersY,uint threashold, bool ready) public {
        require(votings[id].id != 0);
        require(!votings[id].ready);
        require(msg.sender==votings[id].creator);
        require(allowedVotersX.length==allowedVotersY.length);
        require(votings[id].threashold<threashold);
        require(threashold<=allowedVotersX.length+votings[id].votersX.length);
        for (uint i=0; i < allowedVotersX.length; i++) {
            votings[id].votersX.push(allowedVotersX[i]);
            votings[id].votersY.push(allowedVotersY[i]);
        }
        votings[id].ready=ready;
        votings[id].threashold=threashold;
        
    }
    
    struct voting{
        address creator;
        address[] candidatesIDs;
        uint64 id;
        uint256 val;
        uint256 threashold;
        uint256 votecounter;
        uint256[] votersX;
        uint256[] votersY;
        bool done;
        bool ready;
 
        mapping(uint256=>bool) keyimageHashMap;
        mapping(address=>uint) candidates;


        
    }

      modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }
    
    
    function oops() onlyOwner public{
        selfdestruct(msg.sender);
    }
    
    function updateCurve(address curveDest)  onlyOwner public {
        Curve = secp256k(curveDest);
    }
    
    //shows the currents state of a candidate listed in a voting
    //returns true additionaly, if enough people voted with respect to the threashold
    function VoteState(uint64 id,address candidate)  public view returns(bool, uint){
        
       //check if the voting exists
      require(votings[id].id != 0);
         require(votings[id].candidates[candidate] != 0);
         return (votings[id].votecounter >= votings[id].threashold , votings[id].candidates[candidate] );
        
    }
    
    function CompleteVote(uint64 id)  public{
        require(votings[id].id != 0);
        require(votings[id].ready);
        require(!votings[id].done);
        require(votings[id].votecounter>=votings[id].threashold);
        votings[id].done=true;
        
        address[15] memory res;
        uint8 anz;
         (res, anz) = VoteLeaders(id);
        uint256 reward = votings[id].val/anz;
         for(uint8 i=0;i<anz;i++){
             res[i].transfer(reward);
         }
    }
    
    //returns the addresses of the current votings leader (multiple if tie)
    //note that we assume, that at most 15 candidates will have the same amount of votes (returning dyn arrays is bit of a problem in solidity)
    function VoteLeaders(uint64 id)  public view returns(address[15],uint8 amountOfLeadingCandidates){
        require(votings[id].id != 0);
         require(votings[id].ready);
        uint256 max =0;
        require(votings[id].id != 0);
        address[15] memory res;
        uint8 counter=1;
        
        for(uint256 i=0;i<votings[id].candidatesIDs.length;i++){
            uint val = votings[id].candidates[votings[id].candidatesIDs[i]];
            if(val > max ){
                res = [votings[id].candidatesIDs[i],0,0,0,0,0,0,0,0,0,0,0,0,0,0];
                max= val;
                counter=1;
            }else if(val == max){
                res[counter]= votings[id].candidatesIDs[i];
                counter++;
                if(counter==14){
                    counter =1;
                }
            }
        }
        return (res,counter);
        
        
    }
    
    //voteAnnonymous requires a LSAG signature sig(Ix,Iy,c,s[]) which can be produced with the appending golang program
    //the set of cosigners as well as the privatekey corresponding to one of the cosigners listed pubkey are required to create the proof, which then can
    //be passed to this function. The message M we sign is M=(id||candidateId) where || stands for the concatination
    //The Annonymity of this protocol can be resolved by an ethereum transactiongraph, since each voter needs gas to address this contract
    //Neglecting the fact, that ethereum itself is not annonymus, the voting is untraceable (actually its linkable with the propability 1/|voters|)
    //if all cosigners/voters publish their secret (or a commitment to it), the untraceability is broken (as its normal for a ringsignature of this type)
    function VoteAnnonymous(uint64 id, address candidateId, uint256 Ix, uint256 Iy, uint256 c, uint256[] s) public payable {
        require(votings[id].id != 0);
        require(votings[id].ready);
        require(!votings[id].done);
        //proof requires commitment for each voter. NOTE could allow subsets as well..
        //acutally we should set an upper bound of at most 5 - 7 cosigners
        require(s.length==votings[id].votersX.length);
        
        //check if the candidate the vote goes to, exists
        require(votings[id].candidates[candidateId]>=1);
        
        //check for double spend (eg voting twice)
        //we only check Ix, since uint256(keccak256(Ix,Iy))  would be redundant. If we know Ix, Iy only adds 1 bit of additional information +-1
        require(votings[id].keyimageHashMap[ Ix ] == false );
        
        require(verifyRingSignature(candidateId,id, Ix, Iy, c  , s));
        
        votings[id].val = SafeMath.add(votings[id].val,msg.value);
        votings[id].candidates[candidateId] = SafeMath.add(votings[id].candidates[candidateId]  , 1);
        votings[id].votecounter = SafeMath.add(votings[id].votecounter  , 1);
        votings[id].keyimageHashMap[ Ix ] == true;
    }
    
    //verifies LSAG and return true iff valid
    //this is the heart of this contract. It verifies a Linkable Sponataneous Annonymous Group Signature (LSAG) (as it was used in Monero before
    //upgrading to RingCT, see research at getmonero.org for detailed information and proof of LSAG)
    //the signature elements on a given message 'candidateId' are ( (Ix,Iy), c, s ). At current version its assumed, that all allowed voters were taken as cosigners for maximum unlinkability
    function verifyRingSignature(address candidateId, uint64 id, uint256 Ix, uint256 Iy, uint256 c, uint256[] s) internal view returns(bool){
      
        uint256[] memory ci = new uint256[](2);
        ci[0]= c;
        uint256 Lix;
        uint256 Liy;
        uint256 Rix;
        uint256 Riy;
       
       for(uint i=0; i < s.length;i++){
           //we need this helper functions l and r since the max stack depth would be reached otherwise
        (Lix,Liy) = l(s[i],id,i,ci[i%2]);
		(Rix, Riy) = r(s[i],id,i,ci[i%2],Ix,Iy);
		ci[(i+1)%2] = uint256(keccak256(id,candidateId,Lix,Liy,Rix,Riy));
       }
       
       if(ci[s.length%2]==c){
           return true;
       }
       return false;
        
    }
    
    function l(uint256 s, uint64 id,uint i, uint256 ci) internal view returns(uint256 Lx,uint256 Ly){
         uint256 x1;
        uint256 x2;
        uint256 x3;
        uint256 x4;
             (x1,x2) = Curve.ScalarBaseMult(s);
           (x3,x4) = Curve.ScalarMult(votings[id].votersX[i], votings[id].votersY[i] , ci);
           return Curve.Add(x1,x2,x3,x4);
    }
    
    function r(uint256 s, uint64 id,uint i, uint256 ci,uint256 Ix, uint256 Iy)internal view returns(uint256 Rx,uint256 Ry){
        uint256 t1;
        uint256 t2;
        uint256 x3;
        uint256 x4;
        (t1,t2) = Curve.HashToEcc(votings[id].votersX[i], votings[id].votersY[i]);
        (t1, t2) = Curve.ScalarMult(t1, t2, s);
        (x3, x4) = Curve.ScalarMult(Ix, Iy, ci);
		
		return Curve.Add(t1, t2, x3, x4);
    }
    
    
    
}
