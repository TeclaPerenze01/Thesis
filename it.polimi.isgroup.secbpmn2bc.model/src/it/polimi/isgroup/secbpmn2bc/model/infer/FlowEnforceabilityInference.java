package it.polimi.isgroup.secbpmn2bc.model.infer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import it.polimi.isgroup.secbpmn2bc.model.BlockchainType;
import it.polimi.isgroup.secbpmn2bc.model.Definitions;
import it.polimi.isgroup.secbpmn2bc.model.Enforceability;
import it.polimi.isgroup.secbpmn2bc.model.SubProcess;
import it.unitn.disi.sweng.gmt.model.GMTNode;

public class FlowEnforceabilityInference implements SecurityAnnotationInference {

	private List<Combination> getProcessCombinations() {
		List<Combination> result = new ArrayList<Combination>();
		
		//bc any, model true, partial enf
		result.add(new Combination(BlockchainType.PUBLIC,true,Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
		result.add(new Combination(BlockchainType.PRIVATE,true,Enforcement.POSSIBLE, GlobalEnforcement.POSSIBLE.getValue()));
		
		//bc any, model false, no enf
		result.add(new Combination(BlockchainType.PUBLIC,false,Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		result.add(new Combination(BlockchainType.PRIVATE,false,Enforcement.NO_ENFORCEMENT, GlobalEnforcement.NOENF.getValue()));
		
		return result;
	}
	
	@Override
	public void infer(GMTNode node, HashMap<String, List<Combination>> inferredValues, List<ConsoleMessage> messages) {
		if (node instanceof Enforceability) {
			GMTNode element = node.getParent();
			List<Combination> result = null;
			if (element instanceof Definitions || element instanceof Process || element instanceof SubProcess) {
				result = getProcessCombinations();
			} else {
				return;
			}
			inferredValues.merge(element.getUuid(), result, mergeProperties);
			if(result.size() == 0){
				messages.add(new ConsoleMessage(Severity.ERROR, element.getUuid(), "Conflicting privacy constraints hold for element "));
			}
		}
	}

	
}
