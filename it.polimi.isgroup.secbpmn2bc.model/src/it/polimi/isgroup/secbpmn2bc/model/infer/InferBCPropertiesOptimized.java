package it.polimi.isgroup.secbpmn2bc.model.infer;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryUsage;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;


import org.eclipse.emf.ecore.resource.Resource;

import it.polimi.isgroup.secbpmn2bc.model.*;
import it.polimi.isgroup.secbpmn2bc.model.Process;
import it.polimi.isgroup.secbpmn2bc.model.util.ModelNavigator;
import it.unitn.disi.sweng.gmt.model.GMTNode;
import it.unitn.disi.sweng.secbpmn.model.TaskType;

public class InferBCPropertiesOptimized {
	
	public boolean checkForErrors(List<ConsoleMessage> messages) {
		for (ConsoleMessage m : messages){
			if (m.severity == Severity.ERROR){
				return true;
			}
		}
		return false;
	}

	public boolean checkForWarnings(List<ConsoleMessage> messages) {
		for (ConsoleMessage m : messages){
			if (m.severity == Severity.WARNING){
				return true;
			}
		}
		return false;
	}


	public List<ConsoleMessage> annotate(Resource resource, Boolean override){
		

	    long startTime = System.currentTimeMillis();
	  
		Definitions def = (Definitions) resource.getContents().get(0);
		
		// Admissible combinations
		HashMap<String, List<Combination>> result = new HashMap<String, List<Combination>>();
		
		// Find admissible combinations for the whole process (check for indirect dependencies)
	List<ConsoleMessage> messages = determineAdmissibleCombinations(def,result,override);
	    
		if(checkForErrors(messages)){
			return messages;
		}
		
	    // Find best assignment for each element
		propagateDown((GMTNode) def, result, true);
		
	    setBCProperties(def,result);
	    long endTime = System.currentTimeMillis();
	    long runningTime = endTime - startTime;
	    System.out.println("Running time: " + runningTime + " milliseconds");
	    
	 // Get the memory usage
	    MemoryUsage memoryUsage = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();

	    // Format the memory values
	    DecimalFormat decimalFormat = new DecimalFormat("#.##");

	    String usedMemory = decimalFormat.format((double) memoryUsage.getUsed() / (1024 * 1024));
	    String committedMemory = decimalFormat.format((double) memoryUsage.getCommitted() / (1024 * 1024));
	    String maxMemory = decimalFormat.format((double) memoryUsage.getMax() / (1024 * 1024));

	    System.out.println("Memory Usage:");
	    System.out.println("   Used Memory: " + usedMemory + " MB");
	    System.out.println("   Committed Memory: " + committedMemory + " MB");
	    System.out.println("   Max Memory: " + maxMemory + " MB");
	    
	   // CPU.monitorCPUUsage(runningTime);
	    
	  /*  Runtime runtime = Runtime.getRuntime();
	    long usedMemory = runtime.totalMemory() - runtime.freeMemory();
	    System.out.println("Memory Usage: " + usedMemory + " bytes");
	*/    
	    
	    return messages;
	}
	
	public List<ConsoleMessage> checkConstraint(Resource resource){
		
		Definitions def = (Definitions) resource.getContents().get(0);
		
		// Admissible combinations
		HashMap<String, List<Combination>> result = new HashMap<String, List<Combination>>();
		
		// Find admissible combinations for the whole process (check for indirect dependencies)
		List<ConsoleMessage> messages = determineAdmissibleCombinations(def,result,false);
		
		if(checkForErrors(messages)){
			return messages;
		}
		
		propagateDown((GMTNode) def, result, false);
    	
		System.out.println(result);
		
		List<GMTNode> nodes = ModelNavigator.getChildNodes(def);
		
		
		for (GMTNode node : nodes){
			if (node instanceof Definitions) {
				if (((Definitions) node).getOnChainModel() == null) { 
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "Property onChainModel has not been specified for element "));
					System.out.println("Property onChainModel has not been specified for element " + node.toString());
				}
				if (((Definitions) node).getBlockchainType() == BlockchainType.UNDEFINED) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "Property blockchainType has not been specified for element "));
					System.out.println("Property blockchainType has not been specified for element " + node.toString());
				}
			} else if (node instanceof Process) {
				if (((Process) node).getOnChainModel() == null) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "Property onChainModel has not been specified for element "));
					System.out.println("Property onChainModel has not been specified for element " + node.toString());
				}
			} else if (node instanceof SubProcess) {
				if (((SubProcess) node).getOnChainModel() == null) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "Property onChainModel has not been specified for element "));
					System.out.println("Property onChainModel has not been specified for element " + node.toString());
				}
			} else if (node instanceof DataItems) {
				if (((DataItems) node).getOnChainData() == OnChainData.UNDEFINED) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "Property onChainData has not been specified for element "));
					System.out.println("Property onChainData has not been specified for element " + node.toString());
				}
			} else if (node instanceof Task) {
				if (((Task) node).getOnChainExecution() == null) {
					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "Property onChainExecution has not been specified for element "));
					System.out.println("Property onChainExecution has not been specified for element " + node.toString());
				}
			}
			
//			if (node instanceof Definitions || node instanceof Process || 
//					node instanceof SubProcess || node instanceof DataItems ||
//					node instanceof Task) {
//
//				List<Combination> list = result.get(node.getUuid());
//				
//				if (list == null || list.size() == 0) {
//					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "Empty set for element "));
//					System.out.println("Empty set for element " + node.toString());
//				} else if (list.size() > 1) {
//					messages.add(new ConsoleMessage(Severity.WARNING, node.getUuid(), "One or more properties have not been specified for element "));
//					System.out.println("One or more properties for element " + node.toString() + " have not been specified");
//					
//					//TODO: ignorare duplicati o combinazioni non pertinenti per il nodo corrente
//				};
//			}
		}
	    
	    return messages;
	}
	
	
	/**
	 * Determine the admissible attribute combinations that satisfy all security constraints in the model 
	 * @param def process definitions (root node in process tree)
	 * @param result 
	 * @param sets set of admissible attribute combinations for each element (element uuid, combinations)
	 * @param override if true, ignores previously assigned property values
	 * @return information regarding the execution of this function (e.g., conflicting properties)
	 */
	private List<ConsoleMessage> determineAdmissibleCombinations(Definitions def,
			HashMap<String, List<Combination>> result, Boolean override) {
		
		List<ConsoleMessage> messages = new ArrayList<ConsoleMessage>();
		
		List<GMTNode> nodes = ModelNavigator.getChildNodes(def);

		//System.out.println(nodes.toString());
	    
		// Find admissible combinations for each process element (independent from each other)
	    for (GMTNode node : nodes){
	    //	System.out.println(node.toString());
	    	messages.addAll(inferElement(node,result));
	    }
	    
	   // System.out.println(messages.toString());
	    
	    // Check if something went wrong, e.g., conflicting properties hold for the same element
	    if(checkForErrors(messages)){
	    	messages.add(new ConsoleMessage(Severity.ERROR, null, "Errors were found evaluating security annotations"));
		    System.out.println("Errors were found evaluating security annotations");
	    	System.out.println(result);
		    return messages;
	    }
	    
	    messages.add(new ConsoleMessage(Severity.INFORMATION, null, "Finished evaluating security annotations"));
	    System.out.println("Finished evaluating security annotations");
	    System.out.println(result);
	    
	    propagateUp((GMTNode) def, result, messages, override);
	    
		// Check if something went wrong, e.g., properties are incompatible with upper elements in the process tree
	    if(checkForErrors(messages)){
	    	messages.add(new ConsoleMessage(Severity.ERROR, null, "Errors were found determining admissible properties"));
		    System.out.println("Errors were found determining admissible properties");
	    	System.out.println(result);
		    return messages;
	    }
	    
	    messages.add(new ConsoleMessage(Severity.INFORMATION, null, "Finished determining admissible properties"));
	    System.out.println("Finished determining admissible properties");
	    System.out.println(result);
	    
		return messages;
	}
	
	/**
	 * Infer admissible attribute combinations for each element subject to a security constraint
	 * @param element security property
	 * @param result set of admissible attribute combinations for each element (element uuid, combinations)
	 * @return information regarding the execution of this function (e.g., conflicting properties)
	 */
	private List<ConsoleMessage> inferElement(GMTNode element, HashMap<String, List<Combination>> result){
		List<ConsoleMessage> messages = new ArrayList<ConsoleMessage>();
		
		AuditabilityInference aui = new AuditabilityInference();
		AuthenticityInference ati = new AuthenticityInference();
		AvailabilityInference avi = new AvailabilityInference();
		BindOfDutyInference bdi = new BindOfDutyInference();
		FlowEnforceabilityInference fei = new FlowEnforceabilityInference();
		GatewayEnforceabilityInference gei = new GatewayEnforceabilityInference();
		IntegrityInference ii = new IntegrityInference();
		NonDelegationInference ndi = new NonDelegationInference();
		NonRepudiationInference nri = new NonRepudiationInference();
		PrivityInference pi = new PrivityInference();
		SeparationOfDutyInference sdi = new SeparationOfDutyInference();
		
		aui.infer(element, result, messages);
		ati.infer(element, result, messages);
		avi.infer(element, result, messages);
		bdi.infer(element, result, messages);
		fei.infer(element, result, messages);
    	gei.infer(element, result, messages);
    	ii.infer(element, result, messages);
    	ndi.infer(element, result, messages);
    	nri.infer(element, result, messages);
    	pi.infer(element, result, messages);
    	sdi.infer(element, result, messages);
    	
    	return messages;
	}
	
	
	private void setBCProperties(Definitions def, HashMap<String, List<Combination>> result) {
		
		List<GMTNode> nodes = ModelNavigator.getChildNodes(def);

		for (GMTNode node : nodes){
			Combination c = null;
			List<Combination> list = result.get(node.getUuid());
			if (list!=null){
				if (list.size()> 0)
					c = list.get(0);
				else
					//empty set, so a conflict exists
					return;
			} else
				c = new Combination(null,null,0);
			
			if (node instanceof Definitions){
				if (c.blockchainType!=null)
					((Definitions) node).setBlockchainType(c.blockchainType);
				else
					((Definitions) node).setBlockchainType(BlockchainType.PUBLIC);
				
				if (c.onChainModel!=null)
					((Definitions) node).setOnChainModel(c.onChainModel);
				else
					((Definitions) node).setOnChainModel(true);
				
			} else if (node instanceof Process) {
				
				if (c.onChainModel!=null)
					((Process) node).setOnChainModel(c.onChainModel);
				else
					((Process) node).setOnChainModel(true);
			
			} else if (node instanceof SubProcess) {
				
				if (c.onChainModel!=null)
					((SubProcess) node).setOnChainModel(c.onChainModel);
				else
					((SubProcess) node).setOnChainModel(true);
			
			} else if (node instanceof DataItems) {
				
				if (c.onChainData!=null)
					((DataItems) node).setOnChainData(c.onChainData);
				else
					((DataItems) node).setOnChainData(OnChainData.UNENCRYPTED);
			
			} else if (node instanceof Task) {
				
				if (c.onChainExecution!=null)
					((Task) node).setOnChainExecution(c.onChainExecution);
				else
					if (((Task) node).getType()!=TaskType.MANUAL && ((Task) node).getType()!=TaskType.USER)
						((Task) node).setOnChainExecution(true);
					else
						((Task) node).setOnChainExecution(false);
			
			}
		}
		
	}

	private List<Combination> propagateUp(GMTNode node, HashMap<String, List<Combination>> sets,
			List<ConsoleMessage> messages, Boolean override) {
		
		List<Combination> parentCombinations = null; 
		//node has local combinations
		List<Combination> localCombinations = sets.get(node.getUuid());
		//TODO mechanism to handle preset values
		if (!override)
			//constrain combinations based on current property assignments
			localCombinations = constraints(localCombinations, node);
		//TODO end
		if(localCombinations!=null){
			parentCombinations = new ArrayList<Combination>();
			for (Combination c : localCombinations){
				if (node instanceof Task || node instanceof DataItems){
					//select attributes not specific for a task or dataitem
					parentCombinations.add(new Combination(c.blockchainType,c.onChainModel,c.enforcement,c.globalEnforcement));
				} else if (node instanceof Process || node instanceof SubProcess){
					//select attributes not specific for a process or subprocess
					parentCombinations.add(new Combination(c.blockchainType,c.enforcement,c.globalEnforcement));
				} else if (!(node instanceof Definitions)) {
					//select all attributes
					parentCombinations.add(new Combination(c));
				}
			}
		}
		for (GMTNode child : node.getNodes()){
			List<Combination> parentConstraints = new ArrayList<Combination>();
			List<Combination> localConstraints = new ArrayList<Combination>();
			List<Combination> childConstraints = propagateUp(child, sets, messages, override); 
			if(childConstraints != null){
				//compute constraints list
				for (Combination cc : childConstraints){
					if (node instanceof Process || node instanceof SubProcess){
						//local attribute is onChainModel
						localConstraints.add(new Combination(cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
						//parent attribute is blockchainType
						parentConstraints.add(new Combination(cc.blockchainType,cc.enforcement,cc.globalEnforcement));
					} else if (node instanceof Definitions) {
						//local attributes are blockchainType and onChainModel
						localConstraints.add(new Combination(cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement)); 
					} else if (node instanceof Task) {
						//local attribute is onChainExecution
						localConstraints.add(new Combination(cc.onChainExecution,cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
						//parent attributes are blockchainType and onChainModel
						parentConstraints.add(new Combination(cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
					} else if (node instanceof DataItems) {
						//local attribute is onChainData
						localConstraints.add(new Combination(cc.onChainData,cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
						//parent attributes are blockchainType and onChainModel
						parentConstraints.add(new Combination(cc.blockchainType,cc.onChainModel,cc.enforcement,cc.globalEnforcement));
					} else {
						//all attributes must be propagated
						parentConstraints.add(new Combination(cc));
					}
				}
				//current node has some combinations
			//	if(localCombinations!=null){
			//		constrain(localCombinations,localConstraints);
					//a conflict exists among local constraints
			//		if(localCombinations.size()==0){
				//		System.out.println("Errors were found evaluating security annotations");
			//			messages.add(new ConsoleMessage(Severity.ERROR, node.getUuid(), "Conflicting privacy constraints hold for element "));
				//		//TODO decidere se terminare l'esecuzione della funzione.
			//		}
				//child has some local constraints
				//} else if (localConstraints.size()>0){
					localCombinations = factorize(localConstraints);
			//	}
				//a combination for the parent node already exists
				if(parentCombinations!=null){
					constrain(parentCombinations,parentConstraints);
//					//a conflict exists among parent constraints
//					if(parentCombinations.size()==0){
//						SHOULD NEVER HAPPEN
//					}
				//no parent node combination has been defined yet
				} else {
					parentCombinations = new ArrayList<Combination>();
					parentCombinations.addAll(parentConstraints);
				}
			}
		}
		sets.put(node.getUuid(), localCombinations);
		System.out.println("Analyzing: "+node.getUuid());
		System.out.println("Parent combinations: "+parentCombinations);
		System.out.println("Local combinations: "+sets.get(node.getUuid()));
		return parentCombinations;
	}
	
	private void propagateDown(GMTNode node, HashMap<String, List<Combination>> sets, Boolean findBest) {
	
		System.out.println();
		System.out.println("Analyzing: "+node.getUuid());
		
		List<Combination> nodeCombinations = sets.get(node.getUuid());
		List<Combination> parentCombinations;
		
		if(node.getParent()!=null){
			parentCombinations = new ArrayList<Combination>();
		
			
			
			for (Combination parentCombination: sets.get(node.getParent().getUuid())) {
				if (node instanceof Process || node instanceof SubProcess) {
					parentCombinations.add(new Combination(parentCombination.blockchainType, parentCombination.enforcement,parentCombination.globalEnforcement));
				} else {
					parentCombinations.add(new Combination(parentCombination.blockchainType, parentCombination.onChainModel, parentCombination.enforcement ,parentCombination.globalEnforcement));
				}
			}
					
			//some combinations exist for parent node
			if (parentCombinations != null)
				//some combinations exist for current node
				if(nodeCombinations != null)
					constrain(nodeCombinations,parentCombinations);
				//no combinations exist for current node
				else
					nodeCombinations = parentCombinations;
			
		//no combinations exist for parent node, do nothing
		}
		
		System.out.println("Current combinations: "+sets.get(node.getUuid()));
	
		
		if(findBest){
			Combination best = getBestCombination(nodeCombinations);
			
			if (best!=null)
				sets.put(node.getUuid(), new ArrayList<Combination>(Arrays.asList(best)));
			
			System.out.println("Best combination: "+sets.get(node.getUuid()));
		} else
			sets.put(node.getUuid(), nodeCombinations); 
				
		for(GMTNode child : node.getNodes())
			propagateDown(child,sets,findBest);		
	}

	private List<Combination> constraints(List<Combination> nodeCombinations, GMTNode node) {
		List<Combination> result = new ArrayList<Combination>();
		if (nodeCombinations == null) {
			// Create combinations
			if (node instanceof Definitions) {
				if (((Definitions) node).getBlockchainType() != BlockchainType.UNDEFINED) {
					if (((Definitions) node).getOnChainModel() != null)
						result.add(new Combination(((Definitions) node).getBlockchainType(),
								((Definitions) node).getOnChainModel(), Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
					else {
						result.add(new Combination(((Definitions) node).getBlockchainType(), true, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(((Definitions) node).getBlockchainType(), false, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
					}
				} else {
					if (((Definitions) node).getOnChainModel() != null) {
						result.add(new Combination(BlockchainType.PUBLIC, ((Definitions) node).getOnChainModel(),
								Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(BlockchainType.PRIVATE, ((Definitions) node).getOnChainModel(),
								Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					} else {
						result.add(new Combination(BlockchainType.PUBLIC, true, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(BlockchainType.PUBLIC, false, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(BlockchainType.PRIVATE, true, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
						result.add(new Combination(BlockchainType.PRIVATE, false, Enforcement.NATIVE,
								GlobalEnforcement.NATIVE.getValue()));
					}
				}
			}
			if (node instanceof SubProcess)
				if (((SubProcess) node).getOnChainModel() != null) {
					result.add(new Combination(BlockchainType.PRIVATE, ((SubProcess) node).getOnChainModel(),
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(BlockchainType.PUBLIC, ((SubProcess) node).getOnChainModel(),
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				}
			if (node instanceof Process)
				if (((Process) node).getOnChainModel() != null) {
					result.add(new Combination(BlockchainType.PRIVATE, ((Process) node).getOnChainModel(),
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(BlockchainType.PUBLIC, ((Process) node).getOnChainModel(),
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				}
			if (node instanceof DataItems)
				if (((DataItems) node).getOnChainData() != OnChainData.UNDEFINED) {
					result.add(new Combination(((DataItems) node).getOnChainData(), BlockchainType.PRIVATE, true,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((DataItems) node).getOnChainData(), BlockchainType.PUBLIC, true,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((DataItems) node).getOnChainData(), BlockchainType.PRIVATE, false,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((DataItems) node).getOnChainData(), BlockchainType.PUBLIC, false,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				}
			if (node instanceof Task)
				if (((Task) node).getOnChainExecution() != null) {
					result.add(new Combination(((Task) node).getOnChainExecution(), BlockchainType.PRIVATE, true,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((Task) node).getOnChainExecution(), BlockchainType.PUBLIC, true,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((Task) node).getOnChainExecution(), BlockchainType.PRIVATE, false,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
					result.add(new Combination(((Task) node).getOnChainExecution(), BlockchainType.PUBLIC, false,
							Enforcement.NATIVE, GlobalEnforcement.NATIVE.getValue()));
				}
			if (result.size() == 0)
				return null;
		} else {
			// Constrain admissible combinations
			for (Combination c : nodeCombinations) {
				if (node instanceof Definitions)
					if ((((Definitions) node).getBlockchainType() == BlockchainType.UNDEFINED
							|| ((Definitions) node).getBlockchainType() == c.blockchainType)
							&& (((Definitions) node).getOnChainModel() == null
									|| ((Definitions) node).getOnChainModel() == c.onChainModel))
						result.add(c);
				if (node instanceof SubProcess)
					if (((SubProcess) node).getOnChainModel() == null
							|| ((SubProcess) node).getOnChainModel() == c.onChainModel)
						result.add(c);
				if (node instanceof Process)
					if (((Process) node).getOnChainModel() == null
							|| ((Process) node).getOnChainModel() == c.onChainModel)
						result.add(c);
				if (node instanceof DataItems)
					if (((DataItems) node).getOnChainData() == OnChainData.UNDEFINED
							|| ((DataItems) node).getOnChainData() == c.onChainData)
						result.add(c);
				if (node instanceof Task)
					if (((Task) node).getOnChainExecution() == null
							|| ((Task) node).getOnChainExecution() == c.onChainExecution)
						result.add(c);
			}
		}
		return result;
	}

	private Combination getBestCombination(List<Combination> nodeCombinations) {
		Combination c = getSubSet(nodeCombinations,Enforcement.NATIVE);
		if (c!=null)
			return c;
		c = getSubSet(nodeCombinations,Enforcement.POSSIBLE);
		if (c!=null)
			return c;
		c = getSubSet(nodeCombinations,Enforcement.NO_ENFORCEMENT);
		return c;
	}

	public Combination getSubSet(List<Combination> nodeCombinations, Enforcement enforcement) {
		Combination maxEnforcementCombination = null;
		for (Combination c : nodeCombinations) {
			if (c.enforcement == enforcement) {
				if (maxEnforcementCombination == null
						|| c.globalEnforcement > maxEnforcementCombination.globalEnforcement) {
					maxEnforcementCombination = c;
				}
			}
		}
		return maxEnforcementCombination;
	}

	private void constrain(List<Combination> list, List<Combination> constraints) {
		List<Combination> toRemove = new ArrayList<Combination>();
		for(Combination i : list){
			Boolean found = false;
			for(Combination c : constraints){
				if(i.satisfies(c)){
					i.globalEnforcement = (i.globalEnforcement + c.globalEnforcement) / 2;
					found = true;
					break;
				}
			}
			if(!(found)){
				toRemove.add(i);
			}
		}
		for (Combination deleted: toRemove){
			list.remove(deleted);
		}
	}

	private List<Combination> factorize(List<Combination> combinations) {
		List<Combination> newSet = new ArrayList<Combination>();
		for (Combination oldC: combinations){
			boolean keep = true;
			//check if a compatible combination is already present in new set
			for (Combination newC: newSet){
				Combination moreStringent = oldC.compareToFactorize(newC);
				if (moreStringent!=null){
					//replace current combination with more stringent one
					newC = moreStringent;
					keep=false;
				}
			}
			//combination not present yet, add it
			if(keep){
				newSet.add(oldC);
			}
		}
		return newSet;
	}
}