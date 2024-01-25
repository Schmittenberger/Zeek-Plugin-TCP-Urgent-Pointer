# @TEST-EXEC: zeek -NN TCPExtractor::UrgentPointerExtractor |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
