#!/bin/bash

if [ -f .env ]; then
	export $(cat .env | xargs)
fi

export OPENAI_API_KEY=$OPENAI_API_KEY



directory_name=$1
library_name=libtiff

sudo rm -rf /tmp/*
rm -rf ~/.local/share/Trash/files/*

for ((var=1; var<=$2; var++));
do
	sudo rm -rf /tmp/*
	rm -rf ~/.local/share/Trash/files/*

	./run_all_experiments.py\
	--model='gpt-4o'\
	-y ./benchmark-sets/all/${library_name}.yaml\
	--work-dir=results/${library_name}/${directory_name}$var

	python3.11 -m report.web -r results/${library_name}/${directory_name}$var -o outputs/${library_name}/${directory_name}$var
done
