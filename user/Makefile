include header.mk

ucafs: main.cc libucafs.a
	$(CXX) $(CPPFLAGS) -I../common $^ $(LIBS) -o $@

libucafs.a: $(OBJS)
	ar cr $@ $^

%.o: %.cc %.h
	$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@

dirnode.o: dirnode.cc dirnode.h dnode.pb.cc
	$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@

%.pb.cc: %.proto
	protoc --cpp_out=./ $^

.PHONY: clean
clean:
	rm -rf *.pb.h *.pb.cc $(PROGRAM) $(OBJS) libucafs.a
