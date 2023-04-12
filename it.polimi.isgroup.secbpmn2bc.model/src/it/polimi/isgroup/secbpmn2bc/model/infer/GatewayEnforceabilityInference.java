package it.polimi.isgroup.secbpmn2bc.model.infer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import it.polimi.isgroup.secbpmn2bc.model.BlockchainType;
import it.polimi.isgroup.secbpmn2bc.model.DataItems;
import it.polimi.isgroup.secbpmn2bc.model.Enforceability;
import it.polimi.isgroup.secbpmn2bc.model.EnforceabilityScope;
import it.polimi.isgroup.secbpmn2bc.model.OnChainData;
import it.polimi.isgroup.secbpmn2bc.model.Task;
import it.unitn.disi.sweng.gmt.model.GMTNode;
import it.unitn.disi.sweng.gmt.model.GMTRelation;
import it.unitn.disi.sweng.secbpmn.model.Gateway;
import it.unitn.disi.sweng.secbpmn.model.MessageFlow;

public class GatewayEnforceabilityInference implements SecurityAnnotationInference {

	private List<Combination> getDOCombinations(EnforceabilityScope scope) {
		List<Combination> result = new ArrayList<Combination>();

		//public sphere
		if(scope==EnforceabilityScope.PUBLIC){
		
			//data unencrypted, bc public, model any, native enf
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PUBLIC, true, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			result.add(new Combination(OnChainData.UNENCRYPTED, BlockchainType.PUBLIC, false, Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
			
			//data encrypted, bc public, model any, violated
			//no combination should be provided in this case
			
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
			} else {
			
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
		
		}
		return result;
	}
	
	@Override
	public void infer(GMTNode node, HashMap<String, List<Combination>> inferredValues, List<ConsoleMessage> messages) {
		if (node instanceof Enforceability) {
			GMTNode element = node.getParent();
			List<Combination> result = null;
			List<DataItems> dataItems = null;
			
			if (element instanceof Gateway) {
				dataItems = getDataItems((Gateway) element);
				for (DataItems dataItem: dataItems){
					result = getDOCombinations(((Enforceability) node).getScope());
					inferredValues.merge(dataItem.getUuid(), result, mergeProperties);
					if(result.size() == 0){
						messages.add(new ConsoleMessage(Severity.ERROR, element.getUuid(), "Conflicting privacy constraints hold for element "));
					}
				}
			} 
			
		}

	}

	private List<DataItems> getDataItems(Gateway gateway) {
		List<DataItems> result = new ArrayList<DataItems>();
		for(GMTRelation gwIncomingFlow: gateway.getIncomingConnections())
			if(gwIncomingFlow.getSource() instanceof Task)
				for(GMTRelation taskIncomingFlow: gwIncomingFlow.getSource().getIncomingConnections())
					if(taskIncomingFlow instanceof MessageFlow)
						if(taskIncomingFlow.getSource() instanceof DataItems)
							result.add((DataItems) taskIncomingFlow.getSource());
		return result;
	}

}
