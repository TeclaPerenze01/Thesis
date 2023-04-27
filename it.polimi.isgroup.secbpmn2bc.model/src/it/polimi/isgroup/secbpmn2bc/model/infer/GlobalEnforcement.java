package it.polimi.isgroup.secbpmn2bc.model.infer;

public enum GlobalEnforcement {
    NATIVE(1),
    NOENF(0),
    POSSIBLE(0.5);

    private final double value;

    GlobalEnforcement(double value) {
        this.value = value;
    }

    public double getValue() {
        return value;
    }
}