package it.polimi.isgroup.secbpmn2bc.model.infer;

import it.polimi.isgroup.secbpmn2bc.model.*;


public class Combination {
	public Boolean onChainExecution;
	public OnChainData onChainData;
	public BlockchainType blockchainType;
	public Boolean onChainModel;
	public Enforcement enforcement;
	public double globalEnforcement;
	
	//set for tasks
	public Combination(Boolean onChainExecution, BlockchainType blockchainType, Boolean onChainModel, Enforcement enforcement , double globalEnforcement){
		this.onChainExecution = onChainExecution;
		this.onChainData = null;
		this.blockchainType = blockchainType;
		this.onChainModel = onChainModel;
		this.enforcement = enforcement;
		this.globalEnforcement = globalEnforcement;
	}
	
	//set for dataitems
	public Combination(OnChainData onChainData, BlockchainType blockchainType, Boolean onChainModel, Enforcement enforcement, double globalEnforcement){
		this.onChainExecution = null;
		this.onChainData = onChainData;
		this.blockchainType = blockchainType;
		this.onChainModel = onChainModel;
		this.enforcement = enforcement;
		this.globalEnforcement = globalEnforcement;
	}
	
	//set for processes and subprocesses
	public Combination(BlockchainType blockchainType, Boolean onChainModel, Enforcement enforcement,double globalEnforcement){
		this.onChainExecution = null;
		this.onChainData = null;
		this.blockchainType = blockchainType;
		this.onChainModel = onChainModel;
		this.enforcement = enforcement;
		this.globalEnforcement = globalEnforcement;
	}
	
	//set for definitions
	public Combination(BlockchainType blockchainType, Enforcement enforcement,double globalEnforcement){
		this.onChainExecution = null;
		this.onChainData = null;
		this.blockchainType = blockchainType;
		this.onChainModel = null;
		this.enforcement = enforcement;
		this.globalEnforcement = globalEnforcement;
	}
	
	//create a copy
	public Combination(Combination original){
		this.onChainExecution = original.onChainExecution;
		this.onChainData = original.onChainData;
		this.blockchainType = original.blockchainType;
		this.onChainModel = original.onChainModel;
		this.enforcement = original.enforcement;
		this.globalEnforcement = original.globalEnforcement;
	}
		
	public String toString(){
		if(onChainExecution != null)
			return "{onChainExecution: " + onChainExecution + ", blockchainType: " + blockchainType + ", onChainModel: " + onChainModel + ", enforcement: " + enforcement +", globalEnforcement: "+ globalEnforcement +"}";
		else if (onChainData != null)
			return "{onChainData: " + onChainData + ", blockchainType: " + blockchainType + ", onChainModel: " + onChainModel + ", enforcement: " + enforcement + ", globalEnforcement: "+ globalEnforcement +"}";
		else
			return "{blockchainType: " + blockchainType + ", onChainModel: " + onChainModel + ", enforcement: " + enforcement + ", globalEnforcement: "+ globalEnforcement +"}";
	}

	public boolean satisfies(Combination constraint) {
		if(constraint.onChainExecution!=null)
			if(constraint.onChainExecution != this.onChainExecution)
				return false;
		if(constraint.onChainData!=null)
			if(constraint.onChainData != this.onChainData)
				return false;
		if(constraint.blockchainType!=null)
			if(constraint.blockchainType != this.blockchainType)
				return false;
		if(constraint.onChainModel!=null)
			if(constraint.onChainModel != this.onChainModel)
				return false;
		return true;
	}
	
	public Combination compareTo(Combination other){
		if(this.onChainExecution == other.onChainExecution && 
				this.onChainModel == other.onChainModel &&
				this.onChainData == other.onChainData &&
				this.blockchainType == other.blockchainType){
			//old item more stringent or equal than new one
			if(this.enforcement.compareTo(other.enforcement) >= 0){
				this.globalEnforcement = (this.globalEnforcement + other.globalEnforcement) / 2;
				return this;
			//new item more stringent than old one
			} else {
				return other;
			}
		}
		return null;
	}

	
	// need for the optimized version,similar to the previous function but here i need to select the one with lowest GLE
	// this function is called if in the obtained set for parent node after the propagation of children constraints there are similar combinations that do not cause conflict
	// this function select only one combination among the two
	public Combination compareToFactorize(Combination other){
		if(this.onChainExecution == other.onChainExecution && 
				this.onChainModel == other.onChainModel &&
				this.onChainData == other.onChainData &&
				this.blockchainType == other.blockchainType){
			//old item more stringent or equal than new one
			if((this.enforcement.compareTo(other.enforcement) >= 0) && (this.globalEnforcement < other.globalEnforcement)){
			
				return this;
			//new item more stringent than old one
			} else {
				return other;
			}
		}
		return null;
	}
	
	
	public Object remove(String string) {
		// TODO Auto-generated method stub
		return null;
	}
	
}
