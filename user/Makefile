include header.mk

ucafs: main.cc $(OBJS)
	$(CXX) $(CPPFLAGS) $^ $(LIBS) -o $@

%.o: %.cc %.h
	$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@

dirnode.o: dirnode.cc dirnode.h dnode.pb.cc
	$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@

dnode.pb.cc: dnode.proto
	protoc --cpp_out=./ $^

.PHONY: clean
clean:
	rm -rf fbox.pb.h fbox.pb.cc $(PROGRAM) $(OBJS)
