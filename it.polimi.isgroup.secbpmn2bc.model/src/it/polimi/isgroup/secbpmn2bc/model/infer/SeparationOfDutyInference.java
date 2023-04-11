package it.polimi.isgroup.secbpmn2bc.model.infer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import it.polimi.isgroup.secbpmn2bc.model.BlockchainType;
import it.polimi.isgroup.secbpmn2bc.model.DataItems;
import it.polimi.isgroup.secbpmn2bc.model.OnChainData;
import it.polimi.isgroup.secbpmn2bc.model.Task;
import it.polimi.isgroup.secbpmn2bc.model.util.ModelNavigator;
import it.unitn.disi.sweng.gmt.model.GMTElement;
import it.unitn.disi.sweng.gmt.model.GMTNode;
import it.unitn.disi.sweng.gmt.model.GMTRelation;
import it.unitn.disi.sweng.secbpmn.model.Participant;
import it.unitn.disi.sweng.secbpmn.model.SecurityAssociation;
import it.unitn.disi.sweng.secbpmn.model.SeparationOfDuty;
import it.unitn.disi.sweng.secbpmn.model.TaskType;

public class SeparationOfDutyInference implements SecurityAnnotationInference {

	List<Combination> getTaskCombinations(Task task){
		List<Combination> result = new ArrayList<Combination>();
		
		//taskexec false, bc any, model true, possible enf
		result.add(new Combination(false, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
		result.add(new Combination(false, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
		
		//taskexec false, bc any, model false, no enf
		result.add(new Combination(false, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		result.add(new Combination(false, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
				
		if(task.getType() != TaskType.MANUAL && task.getType() != TaskType.USER) {
			//taskexec true, bc any, model false, no enf
			result.add(new Combination(true, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(true, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			
			//taskexec true, bc any, model true, native enf
			result.add(new Combination(true, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(true, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
		}
		
		return result;
	}
	
	List<Combination> getDICombinations(DataItems dataItem){
		
		List<Combination> result = new ArrayList<Combination>();
		
		//data digest, bc any, model true, native enf
		result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
		result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
		
		//data unencrypted, bc any, model true, native enf
		result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
		result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
		
		//data encrypted, bc any, model true, native enf
		result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
		result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
		
		
		//data none, bc any, model true, possible enf
		result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
		result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
		
		
		//data none, bc any, model false, no enf
		result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		
		//data digest, bc any, model false, no enf
		result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		
		//data unencrypted, bc any, model false, no enf
		result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		
		//data encrypted, bc any, model false, no enf
		result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		
		return result;
	}
	
	public List<GMTNode> getPools(SeparationOfDuty node){
		List<GMTNode> pools = new ArrayList<GMTNode>();
		//identify outgoing security associations
		for (GMTRelation edge: ((SeparationOfDuty) node).getOutgoingConnections()){
			if(edge instanceof SecurityAssociation){
				//identify pools
				if (((SecurityAssociation) edge).getTarget() instanceof Participant){
					pools.add((GMTNode) ((SecurityAssociation) edge).getTarget());
				} else if (((SecurityAssociation) edge).getSource() instanceof Participant){
					pools.add((GMTNode) ((SecurityAssociation) edge).getSource());
				}	
			}
		}
		//identify incoming security associations
		for (GMTRelation edge: ((SeparationOfDuty) node).getIncomingConnections()){
			if(edge instanceof SecurityAssociation){
				//identify pools
				if (((SecurityAssociation) edge).getTarget() instanceof Participant){
					pools.add((GMTNode) ((SecurityAssociation) edge).getTarget());
				} else if (((SecurityAssociation) edge).getSource() instanceof Participant){
					pools.add((GMTNode) ((SecurityAssociation) edge).getSource());
				}	
			}
		}
		return pools;
	}
	
	public void infer(GMTNode node, HashMap<String, List<Combination>> inferredValues, List<ConsoleMessage> messages){
		if (node instanceof SeparationOfDuty) {
			//identify outgoing security associations
			for (GMTElement pool: getPools((SeparationOfDuty) node)){
				//get all elements inside that pool
				for (GMTNode element : ModelNavigator.getChildNodes((GMTNode) pool)){
					//define for each element the property combinations
					List<Combination> result = null; // = new ArrayList<Combination>();
					if (element instanceof Task) {
						result = getTaskCombinations((Task) element);
					} else if (element instanceof DataItems) {
						result = getDICombinations((DataItems) element);
					} 
					//merge current combinations with existing ones
					if(result != null) {
						inferredValues.merge(element.getUuid(), result, mergeProperties);
						if(result.size() == 0){
							messages.add(new ConsoleMessage(Severity.ERROR, element.getUuid(), "Conflicting privacy constraints hold for element "));
						}
					}  
				}
			}
		}
	}
}
