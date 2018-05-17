gcc unary_trietree_test.c -o unarybit
echo "gcc unary_trietree_test.c -o unarybit"
gcc multibit_trietree_test.c -o multibit
echo "gcc multibit_trietree_test.c -o multibit"
echo " "

python gen_test_txt.py

echo "Search Cost:"
./unarybit ./forwarding-table.txt ./forwarding-table.txt
./multibit ./forwarding-table.txt

rm multibit unarybit