#!/bin/sh

echo "// ver.h">ver.h
echo "//">>ver.h 
echo "// add version and build date and time">>ver.h
echo "// Note: This file was automatically generated">>ver.h
echo "//       don't edit it">>ver.h
echo "">>ver.h

echo "#ifndef _VER_H">>ver.h
echo "#define _VER_H">>ver.h
echo "">>ver.h
echo "#define BUILDTIME \"`date +%Y.%m.%d-%H:%M:%S`\"">>ver.h