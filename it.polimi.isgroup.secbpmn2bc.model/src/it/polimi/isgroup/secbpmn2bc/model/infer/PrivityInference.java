package it.polimi.isgroup.secbpmn2bc.model.infer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import it.polimi.isgroup.secbpmn2bc.model.BlockchainType;
import it.polimi.isgroup.secbpmn2bc.model.DataItems;
import it.polimi.isgroup.secbpmn2bc.model.Message;
import it.polimi.isgroup.secbpmn2bc.model.OnChainData;
import it.polimi.isgroup.secbpmn2bc.model.PrivityScope;
import it.polimi.isgroup.secbpmn2bc.model.PrivitySphere;
import it.polimi.isgroup.secbpmn2bc.model.Task;
import it.unitn.disi.sweng.gmt.model.GMTElement;
import it.unitn.disi.sweng.gmt.model.GMTNode;
import it.unitn.disi.sweng.gmt.model.GMTRelation;
import it.unitn.disi.sweng.secbpmn.model.DataAssociation;
import it.unitn.disi.sweng.secbpmn.model.TaskType;

public class PrivityInference implements SecurityAnnotationInference {

	private List<Combination> getDOCombinations(DataItems dataObject, PrivityScope scope) {
		List<Combination> result = new ArrayList<Combination>();

		//public sphere
		if(scope==PrivityScope.PUBLIC){

			//data unencrypted, bc public, model any, native enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			
			//data encrypted, bc public, model any, possible enf
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data (un)encrypted, bc private, model any, native enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			
			//data digest, bc any, model any, possible enf
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data none, bc any, model any, no enf
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		
		//private sphere
		} else if (scope==PrivityScope.PRIVATE){
			
			//data unencrypted, bc public, model any, violated
			//no combination should be provided in this case
			
			//data encrypted, bc public, model any, possible enf
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data (un)encrypted, bc private, model any, native enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			
			//data digest, bc any, model any, possible enf
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data none, bc any, model any, no enf
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			
		//static, weak-dynamic and strong-dynamic spheres
		} else {
			//data unencrypted, bc public, model any, violated
			//no combination should be provided in this case
			
			//data encrypted, bc public, model any, possible enf
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data (un)encrypted, bc private, model any, possible enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data digest, bc any, model any, possible enf
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data none, bc any, model any, no enf
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		
		}
		return result;
	}

	private List<Combination> getMessageCombinations(Message dataObject, PrivityScope scope) {
		List<Combination> result = new ArrayList<Combination>();
		
		//public sphere
		if(scope==PrivityScope.PUBLIC){
			//data unencrypted, bc public, model any, native enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			
			//data encrypted, bc public, model any, native enf
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data (un)encrypted, bc private, model any, native enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			
			//data digest, bc any, model any, possible enf
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data none, bc any, model any, no enf
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		
		// private sphere
		} else if(scope==PrivityScope.PRIVATE){
			//data unencrypted, bc public, model any, violated
			//no combination should be provided in this case
			
			//data encrypted, bc public, model any, possible enf
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data (un)encrypted, bc private, model any, native enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			
			//data digest, bc any, model any, possible enf
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data none, bc any, model any, no enf
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			
		//strong-dynamic sphere
		} else if(scope==PrivityScope.STRONG_DYNAMIC){
			//data unencrypted, bc public, model any, violated
			//no combination should be provided in this case
			
			//data encrypted, bc public, model any, native enf
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			
			//data (un)encrypted, bc private, model any, native enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data digest, bc any, model any, possible enf
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data none, bc any, model any, no enf
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		
		//static and weak-dynamic spheres
		} else {
			
			//data unencrypted, bc public, model any, violated
			//no combination should be provided in this case
			
			//data encrypted, bc public, model any, possible enf
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data (un)encrypted, bc private, model any, possible enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.ENCRYPTED, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data digest, bc any, model any, possible enf
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PUBLIC, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, true, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			result.add(new Combination(OnChainData.DIGEST, BlockchainType.PRIVATE, false, Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
			
			//data none, bc any, model any, no enf
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(OnChainData.NONE, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			
		}
		return result;
	}
	
	private List<Combination> getTaskCombinations(Task task, PrivityScope scope) {
		List<Combination> result = new ArrayList<Combination>();
		
		//TODO: revise once rules have been finalized
		
		//public sphere
		if(scope==PrivityScope.PUBLIC){
		
			//taskexec false, bc any, model any, native enf
			result.add(new Combination(false, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(false, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(false, BlockchainType.PUBLIC, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(false, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					
			if(task.getType() != TaskType.MANUAL && task.getType() != TaskType.USER) {

				//taskexec true, bc any, model any, native enf
				result.add(new Combination(true, BlockchainType.PUBLIC, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				result.add(new Combination(true, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				result.add(new Combination(true, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				result.add(new Combination(true, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			}
			
		//private, static, weak-dynamic and strong-dynamic spheres
		} else {
			//taskexec false, bc any, model any, no enf
			result.add(new Combination(false, BlockchainType.PUBLIC, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(false, BlockchainType.PRIVATE, true, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(false, BlockchainType.PUBLIC, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			result.add(new Combination(false, BlockchainType.PRIVATE, false, Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
			
			if(task.getType() != TaskType.MANUAL && task.getType() != TaskType.USER) {

				//taskexec true, bc public, model any, violated
				//no combination should be provided in this case
			
				//taskexec true, bc private, model any, native enf
				result.add(new Combination(true, BlockchainType.PRIVATE, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				result.add(new Combination(true, BlockchainType.PRIVATE, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			}
		}
		return result;
	}
	
	@Override
	public void infer(GMTNode node, HashMap<String, List<Combination>> inferredValues, List<ConsoleMessage> messages) {
		if (node instanceof PrivitySphere){
			GMTNode dataItem = node.getParent();
			List<Combination> result = null;
			List<Task> tasks = null;
			
			if (dataItem instanceof DataItems){
				
				if (dataItem instanceof Message)
					result = getMessageCombinations((Message) dataItem, ((PrivitySphere) node).getScope());
				else  
					result = getDOCombinations((DataItems) dataItem, ((PrivitySphere) node).getScope());
				
				inferredValues.merge(dataItem.getUuid(), result, mergeProperties);
				if(result.size() == 0){
					messages.add(new ConsoleMessage(Severity.ERROR, dataItem.getUuid(), "Conflicting privacy constraints hold for element "));
				}
				
				tasks = getTasks((DataItems) dataItem);
				
				for (Task task: tasks){
					result = getTaskCombinations(task, ((PrivitySphere) node).getScope());
					inferredValues.merge(task.getUuid(), result, mergeProperties);
					if(result.size() == 0){
						messages.add(new ConsoleMessage(Severity.ERROR, task.getUuid(), "Conflicting privacy constraints hold for element "));
					}
				}
			} 
		}
	}

	private List<Task> getTasks(DataItems dataItem) {
		List<Task> result = new ArrayList<Task>();
		if(dataItem instanceof Message){
			//TODO: define logic for messages
		} else {
			for(GMTRelation edge: dataItem.getOutgoingConnections()){
				if (edge instanceof DataAssociation){
					GMTElement node = edge.getTarget();
					if (node instanceof Task)
						result.add((Task) node);
				}
			}
			for(GMTRelation edge: dataItem.getIncomingConnections()){
				if (edge instanceof DataAssociation){
					GMTElement node = edge.getSource();
					if (node instanceof Task)
						result.add((Task) node);
				}
			}
		}
		return result;
	}
}
