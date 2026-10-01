P4C ?= p4c-vitisnet
M4 ?= m4
RUN_P4BM ?= run-p4bm-vitisnet
PYTHON ?= python3

M4FLAGS = --synclines -I ${SRC}
P4FLAGS :=
BUILD_DIR := build
PYTHONPATH := "${XILINX_VIVADO}/tps/lib/python3.8:${PYTHONPATH}"


SRC := scitra
INGRESS_CLASSIFIER_SRC := ${SRC}/ingress_classifier.p4 \
	${SRC}/include/limits.p4 \
	${SRC}/include/headers.p4
INGRESS_TRANSLATOR_SRC := ${SRC}/ingress_translator.p4 \
	${SRC}/include/headers.p4 \
	${SRC}/include/address_mapping.p4
EGRESS_TRANSLATOR_SRC := ${SRC}/egress_translator.p4 \
	${SRC}/include/limits.p4 \
	${SRC}/include/headers.p4 \
	${SRC}/include/cpu_header.p4 \
	${SRC}/include/address_mapping.p4
EGRESS_CHECKSUM_SRC := ${SRC}/egress_checksum.p4 \
	${SRC}/include/headers.p4

.PHONY: all ingress-classifier ingress-translator egress-translator egress-checksum

all: ingress-classifier ingress-translator egress-translator egress-checksum

${BUILD_DIR}:
	mkdir -p ${BUILD_DIR}

%.json : %.p4
	${P4C} $(P4FLAGS) $< -o $@


# Build dataplane
ingress-classifier: ${BUILD_DIR}/ingress-classifier.json

${BUILD_DIR}/ingress-classifier.p4: ${INGRESS_CLASSIFIER_SRC} | ${BUILD_DIR}
	${M4} ${M4FLAGS} $< > $@

ingress-translator: ${BUILD_DIR}/ingress-translator.json

${BUILD_DIR}/ingress-translator.p4: ${INGRESS_TRANSLATOR_SRC} | ${BUILD_DIR}
	${M4} ${M4FLAGS} $< > $@

egress-translator: ${BUILD_DIR}/egress-translator.json

${BUILD_DIR}/egress-translator.p4: ${EGRESS_TRANSLATOR_SRC} | ${BUILD_DIR}
	${M4} ${M4FLAGS} $< > $@

egress-checksum: ${BUILD_DIR}/egress-checksum.json

${BUILD_DIR}/egress-checksum.p4: ${EGRESS_CHECKSUM_SRC} | ${BUILD_DIR}
	${M4} ${M4FLAGS} $< > $@

# Behavioral Simulation
.PHONY: sim sim-ingress-classifier sim-ingress-translator sim-egress-translator sim-egress-checksum

sim: sim-ingress-classifier sim-ingress-translator sim-egress-translator sim-egress-checksum

sim-ingress-classifier: ingress-classifier
	PYTHONPATH=${PYTHONPATH} python3 -m unittest discover -s tests -p 'test_ingress_classifier*'

sim-ingress-translator: ingress-translator
	PYTHONPATH=${PYTHONPATH} python3 -m unittest discover -s tests -p 'test_ingress_translator*'

sim-egress-translator: egress-translator
	PYTHONPATH=${PYTHONPATH} python3 -m unittest discover -s tests -p 'test_egress_translator*'

sim-egress-checksum: egress-checksum
	PYTHONPATH=${PYTHONPATH} python3 -m unittest discover -s tests -p 'test_egress_checksum*'

# Cleaning
.PHONY: clean
clean:
	@rm -r ${BUILD_DIR} || true
	@rm *.user *.meta *.log || true
