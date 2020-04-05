# Makefile
# Copyright 2020 by Rickard E. (Rik) Faith

.PHONY: lint

DLIST:=missing-function-docstring,missing-module-docstring
DLIST:=$(DLIST),missing-class-docstring,too-few-public-methods
DLIST:=$(DLIST),too-many-arguments,too-many-locals,too-many-instance-attributes
DLIST:=$(DLIST),too-many-branches

lint:
	pep8 bin/urm urm/*.py
	pylint --disable=$(DLIST) \
		--include-naming-hint=y \
		--good-names=fp \
		urm

wheel:
	python3 setup.py sdist bdist_wheel

